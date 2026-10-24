package updateproof

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type payloadFile struct {
	data           []byte
	mode, uid, gid uint32
}
type debPayload struct {
	control   map[string]string
	files     map[string]payloadFile
	md5       map[string]string
	conffiles map[string]bool
}

func arMembers(b []byte) (map[string][]byte, error) {
	if !bytes.HasPrefix(b, []byte("!<arch>\n")) {
		return nil, ErrChain
	}
	out := map[string][]byte{}
	b = b[8:]
	for len(b) > 0 {
		if len(b) < 60 || string(b[58:60]) != "`\n" {
			return nil, ErrChain
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(b[:16])), "/")
		n, e := strconv.ParseInt(strings.TrimSpace(string(b[48:58])), 10, 64)
		if e != nil || n < 0 || n > int64(len(b)-60) || out[name] != nil || len(out) >= 3 {
			return nil, ErrChain
		}
		b = b[60:]
		out[name] = bytes.Clone(b[:n])
		b = b[n:]
		if n%2 != 0 {
			if len(b) == 0 || b[0] != '\n' {
				return nil, ErrChain
			}
			b = b[1:]
		}
	}
	if len(out) != 3 || string(out["debian-binary"]) != "2.0\n" {
		return nil, ErrChain
	}
	return out, nil
}
func archivePart(ctx context.Context, p Profile, deb []byte, members map[string][]byte, prefix string) (map[string]payloadFile, error) {
	var raw []byte
	found := false
	for name, b := range members {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if found {
			return nil, ErrChain
		}
		found = true
		switch name {
		case prefix:
			raw = b
		case prefix + ".gz":
			gz, e := gzip.NewReader(bytes.NewReader(b))
			if e != nil {
				return nil, ErrChain
			}
			raw, e = io.ReadAll(io.LimitReader(gz, p.Limits.Bytes+1))
			ce := gz.Close()
			if e != nil || ce != nil || int64(len(raw)) > p.Limits.Bytes {
				return nil, ErrChain
			}
		case prefix + ".xz", prefix + ".zst":
			var e error
			raw, e = decodeDeb(ctx, p, deb, prefix)
			if e != nil {
				return nil, e
			}
		default:
			return nil, ErrChain
		}
	}
	if !found {
		return nil, ErrChain
	}
	return tarFiles(ctx, raw, p.Limits)
}
func decodeDeb(ctx context.Context, p Profile, deb []byte, part string) ([]byte, error) {
	f, e := pinnedTool(p.DPKGDeb)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	dir, e := os.MkdirTemp("", "swarma-update-deb-")
	if e != nil {
		return nil, ErrStore
	}
	defer os.RemoveAll(dir)
	name := filepath.Join(dir, "archive.deb")
	if os.WriteFile(name, deb, 0600) != nil {
		return nil, ErrStore
	}
	flag := "--fsys-tarfile"
	if part == "control.tar" {
		flag = "--ctrl-tarfile"
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "/proc/self/fd/3", flag, name)
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{}
	cmd.Dir = dir
	out, errout := &boundedBuffer{limit: p.Limits.Bytes}, &boundedBuffer{limit: 65536}
	cmd.Stdout = out
	cmd.Stderr = errout
	if cmd.Run() != nil {
		return nil, ErrChain
	}
	return bytes.Clone(out.Bytes()), nil
}
func tarFiles(ctx context.Context, b []byte, l Limits) (map[string]payloadFile, error) {
	if int64(len(b)) > l.Bytes {
		return nil, ErrChain
	}
	reader := bytes.NewReader(b)
	tr := tar.NewReader(reader)
	out := map[string]payloadFile{}
	seen := map[string]bool{}
	count := 0
	var total int64
	for {
		if ctx.Err() != nil {
			return nil, ErrChain
		}
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrChain
		}
		count++
		if count > l.Members || h.Size < 0 || h.Size > l.Bytes-total || len(h.PAXRecords) > 0 || h.Uid < 0 || h.Gid < 0 || h.Mode < 0 || h.Mode > 07777 {
			return nil, ErrChain
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "." || name == "" {
			if h.Typeflag == tar.TypeDir {
				continue
			}
			return nil, ErrChain
		}
		if path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\x00\n\r") || seen[name] {
			return nil, ErrChain
		}
		seen[name] = true
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		case tar.TypeSymlink, tar.TypeLink:
			continue
		default:
			return nil, ErrChain
		}
		data, e := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(data)) != h.Size {
			return nil, ErrChain
		}
		total += int64(len(data))
		out[name] = payloadFile{data, uint32(h.Mode), uint32(h.Uid), uint32(h.Gid)}
	}
	remaining, _ := io.ReadAll(reader)
	for _, v := range remaining {
		if v != 0 {
			return nil, ErrChain
		}
	}
	return out, nil
}
func readDeb(ctx context.Context, p Profile, b []byte) (debPayload, error) {
	fail := func(e error) (debPayload, error) { return debPayload{}, e }
	members, e := arMembers(b)
	if e != nil {
		return fail(e)
	}
	control, e := archivePart(ctx, p, b, members, "control.tar")
	if e != nil {
		return fail(e)
	}
	files, e := archivePart(ctx, p, b, members, "data.tar")
	if e != nil {
		return fail(e)
	}
	c, ok := control["control"]
	if !ok {
		return fail(ErrChain)
	}
	fields, e := parseOne(c.data)
	if e != nil {
		return fail(e)
	}
	md5s := map[string]string{}
	for _, line := range strings.Split(string(control["md5sums"].data), "\n") {
		if line == "" {
			continue
		}
		s := strings.Fields(line)
		if len(s) != 2 || len(s[0]) != 32 || md5s[s[1]] != "" {
			return fail(ErrChain)
		}
		md5s[s[1]] = s[0]
	}
	conffiles := map[string]bool{}
	for _, line := range strings.Split(string(control["conffiles"].data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			conffiles[strings.TrimPrefix(strings.Fields(line)[0], "/")] = true
		}
	}
	return debPayload{fields, files, md5s, conffiles}, nil
}
