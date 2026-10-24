//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Finite byte budgets apply to implementation hashing, including large ELF data
// members. Configuration/document reads keep their existing smaller limits.
const ImplementationFileBytes int64 = 64 << 20
const ImplementationTotalBytes int64 = 256 << 20

func openImplementation(ctx context.Context, a ProtectedArtifact, max int64) (_ *os.File, file ClosureFile, size int64, err error) {
	if max < 1 {
		return nil, file, 0, refusal("directory_unknown", "implementation_byte_limit", nil)
	}
	if max > ImplementationFileBytes || a.Directory == nil || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || filepath.Base(a.Path) != a.Name {
		return nil, file, 0, refusal("directory_unknown", "implementation_input", nil)
	}
	if e := ctx.Err(); e != nil {
		return nil, file, 0, e
	}
	if e := a.Directory.protected(); e != nil {
		return nil, file, 0, e
	}
	probe, e := child(a.Directory.f, a.Name, unix.O_PATH, 0)
	if e != nil {
		return nil, file, 0, e
	}
	st, e := descriptorStat(probe)
	e = errors.Join(e, probe.Close())
	if e != nil {
		return nil, file, 0, e
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != a.Directory.owner || st.Gid != a.Directory.group || st.Mode&0022 != 0 {
		return nil, file, 0, refusal("directory_unknown", "closure_protection", nil)
	}
	if st.Size < 0 || st.Size > max {
		return nil, file, 0, refusal("directory_unknown", "implementation_byte_limit", nil)
	}
	f, e := child(a.Directory.f, a.Name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, file, 0, e
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	before, e := descriptorStat(f)
	if e != nil || !stableStat(st, before) {
		return nil, file, 0, refusal("path_changed", "implementation_open", e)
	}
	if e = access(f); e != nil {
		return nil, file, 0, e
	}
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return nil, file, 0, e
		}
		n, x := f.Read(buf)
		total += int64(n)
		if total > max {
			return nil, file, 0, refusal("directory_unknown", "implementation_byte_limit", nil)
		}
		if n > 0 {
			_, _ = hash.Write(buf[:n])
		}
		if x == io.EOF {
			break
		}
		if x != nil {
			return nil, file, 0, x
		}
		if n == 0 {
			return nil, file, 0, io.ErrNoProgress
		}
	}
	after, e := descriptorStat(f)
	if e != nil || total != before.Size || !stableStat(before, after) {
		return nil, file, 0, refusal("path_changed", "implementation_hash", e)
	}
	if e = ctx.Err(); e != nil {
		return nil, file, 0, e
	}
	return f, ClosureFile{Path: a.Path, SHA256: hex.EncodeToString(hash.Sum(nil))}, total, nil
}

// CaptureImplementationFile streams one protected file with explicit caller and
// fixed ceilings. It does not load code or attest the completeness of a closure.
func CaptureImplementationFile(ctx context.Context, a ProtectedArtifact, max int64) (ClosureFile, int64, error) {
	f, file, size, e := openImplementation(ctx, a, max)
	if e != nil {
		return ClosureFile{}, 0, e
	}
	if e = f.Close(); e != nil {
		return ClosureFile{}, 0, e
	}
	return file, size, nil
}
