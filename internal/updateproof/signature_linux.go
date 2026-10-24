//go:build linux

package updateproof

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type boundedBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.limit {
		return 0, ErrScope
	}
	return b.Buffer.Write(p)
}
func pinnedFile(pin FilePin, owner uint32, anchor string, limit int64) (*os.File, error) {
	if !leafPath(pin.Path) || !digestOK(pin.SHA256) {
		return nil, ErrTool
	}
	d, e := openProtectedDir(filepath.Dir(pin.Path), owner, anchor)
	if e != nil {
		return nil, ErrTool
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), filepath.Base(pin.Path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrTool
	}
	f := os.NewFile(uintptr(fd), pin.Path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&06000 != 0 || st.Size > limit {
		f.Close()
		return nil, ErrTool
	}
	for _, n := range []string{"system.posix_acl_access", "security.capability"} {
		if _, e := unix.Fgetxattr(fd, n, nil); e != unix.ENODATA {
			f.Close()
			return nil, ErrTool
		}
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit || Digest(b) != pin.SHA256 {
		f.Close()
		return nil, ErrTool
	}
	if _, e = f.Seek(0, 0); e != nil {
		f.Close()
		return nil, ErrTool
	}
	return f, nil
}
func pinnedTool(t Tool) (*os.File, error) {
	for _, p := range t.Dependencies {
		f, e := pinnedFile(p, 0, "/", 128<<20)
		if e != nil {
			return nil, e
		}
		f.Close()
	}
	return pinnedFile(FilePin{t.Path, t.SHA256}, 0, "/", 128<<20)
}
func authenticate(ctx context.Context, p Profile, b Bundle, clock Clock) ([]byte, string, error) {
	tool, e := pinnedTool(p.GPGV)
	if e != nil {
		return nil, "", e
	}
	defer tool.Close()
	anchor := "/"
	if p.fileOwner != 0 {
		anchor = filepath.Dir(p.Keyring.Path)
	}
	key, e := pinnedFile(p.Keyring, p.fileOwner, anchor, p.Limits.Bytes)
	if e != nil {
		return nil, "", e
	}
	defer key.Close()
	// Only retained local bytes enter a private temporary verifier directory.
	// gpgv has no configuration files; an explicit keyring excludes its defaults.
	dir, e := os.MkdirTemp("", "swarma-update-proof-")
	if e != nil {
		return nil, "", ErrStore
	}
	defer os.RemoveAll(dir)
	if os.WriteFile(filepath.Join(dir, "release"), b.Release, 0600) != nil {
		return nil, "", ErrStore
	}
	args := []string{"--homedir", dir, "--keyring", "/proc/self/fd/4", "--status-fd", "2", "--output", "-"}
	if len(b.Signature) > 0 {
		if os.WriteFile(filepath.Join(dir, "signature"), b.Signature, 0600) != nil {
			return nil, "", ErrStore
		}
		args = append(args, filepath.Join(dir, "signature"), filepath.Join(dir, "release"))
	} else {
		if !bytes.HasPrefix(b.Release, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
			return nil, "", ErrTrust
		}
		args = append(args, filepath.Join(dir, "release"))
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{tool, key}
	cmd.Env = []string{}
	cmd.Dir = dir
	out, status := &boundedBuffer{limit: p.Limits.Bytes}, &boundedBuffer{limit: 65536}
	cmd.Stdout = out
	cmd.Stderr = status
	if cmd.Run() != nil {
		return nil, "", ErrTrust
	}
	signer := ""
	valid := 0
	for _, line := range strings.Split(status.String(), "\n") {
		if !strings.HasPrefix(line, "[GNUPG:] ") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "[GNUPG:] "))
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED", "FAILURE", "NODATA":
			return nil, "", ErrTrust
		case "VALIDSIG":
			if len(f) < 10 {
				return nil, "", ErrTrust
			}
			created, e1 := strconv.ParseInt(f[3], 10, 64)
			expires, e2 := strconv.ParseInt(f[4], 10, 64)
			if e1 != nil || e2 != nil || created > clock.Now.Add(p.FutureSkew).Unix() || expires != 0 && expires <= clock.Now.Unix() || (f[7] != "1" && f[7] != "22") || (f[8] != "8" && f[8] != "9" && f[8] != "10") || (f[9] != "00" && f[9] != "01") {
				return nil, "", ErrTrust
			}
			allowed := false
			for _, s := range p.Signers {
				if s.Fingerprint == f[1] && !s.Revoked && !s.NotBefore.IsZero() && s.NotAfter.After(s.NotBefore) && !clock.Now.Before(s.NotBefore) && clock.Now.Before(s.NotAfter) && !time.Unix(created, 0).Before(s.NotBefore) && time.Unix(created, 0).Before(s.NotAfter) {
					allowed = true
				}
			}
			if !allowed {
				return nil, "", ErrTrust
			}
			valid++
			signer = f[1]
		}
	}
	if valid != 1 {
		return nil, "", ErrTrust
	}
	if len(b.Signature) > 0 {
		return bytes.Clone(b.Release), signer, nil
	}
	return bytes.Clone(out.Bytes()), signer, nil
}
