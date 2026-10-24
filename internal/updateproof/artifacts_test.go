//go:build linux

package updateproof

import (
	"errors"
	"os"
	"testing"
)

// Claim: visible bytes after either file or directory sync failure do not allow
// a matching retry to skip durability. Owned fault injection is not power-loss qualification.
func TestReviewArtifactRetryDurability(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			path := t.TempDir()
			if e := os.Chmod(path, 0700); e != nil {
				t.Fatal(e)
			}
			d, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			limits := Limits{Bytes: 1 << 20, Entries: 100, Members: 100}
			failed := errors.New("owned sync failure")
			fault := func(f *os.File) error {
				st, e := f.Stat()
				if e != nil {
					return e
				}
				if st.IsDir() == directory {
					return failed
				}
				return f.Sync()
			}
			write := func(sync func(*os.File) error) error {
				return retainArtifactAt(d, uint32(os.Getuid()), []byte("retained payload"), limits, sync)
			}
			if e = write(fault); e != ErrStore {
				t.Fatalf("first write must expose sync failure: %v", e)
			}
			if e = write(fault); e != ErrStore {
				t.Fatalf("matching retry bypassed failed sync: %v", e)
			}
			fileSync, dirSync := 0, 0
			good := func(f *os.File) error {
				st, e := f.Stat()
				if e != nil {
					return e
				}
				if st.IsDir() {
					dirSync++
				} else {
					fileSync++
				}
				return f.Sync()
			}
			if e = write(good); e != nil {
				t.Fatal(e)
			}
			if fileSync != 1 || dirSync != 1 {
				t.Fatalf("retry syncs file=%d directory=%d", fileSync, dirSync)
			}
		})
	}
}
