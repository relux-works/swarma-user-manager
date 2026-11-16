package launch

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
)

// splitPath accepts only a clean absolute path with a protected parent below
// the filesystem root; anything else yields empty components.
func splitPath(p string) (dir, base string) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return "", ""
	}
	dir, base = filepath.Dir(p), filepath.Base(p)
	if dir == "/" || base == "" || base == "." || base == ".." {
		return "", ""
	}
	return dir, base
}

// streamDigest hashes at most max bytes from an open handle; longer content
// is refused rather than truncated.
func streamDigest(r io.Reader, max int64) (string, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, max+1))
	if e != nil || n > max {
		return "", fail("executable_digest_mismatch")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
