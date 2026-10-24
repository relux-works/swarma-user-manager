//go:build linux

package updateproof

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Claim: even a database-only field, ownership/checksum entry, pending update or
// trigger changes the snapshot digest. Root lock file contents are explicitly
// excluded; symlinks and over-budget objects refuse rather than disappear.
func TestReconcileDatabaseDigest(t *testing.T) {
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	write := func(name, data string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(d, name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("status", "Package: fixture\nStatus: install ok installed\n")
	f, e := os.Open(d)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	limits := Limits{Bytes: 1 << 20, Entries: 100, Members: 100}
	digest := func() (string, error) { return databaseDigest(context.Background(), f, uint32(os.Getuid()), limits) }
	before, e := digest()
	if e != nil {
		t.Fatal(e)
	}
	write("lock-frontend", "excluded lock")
	same, e := digest()
	if e != nil || same != before {
		t.Fatal("lock content affected semantic digest", e)
	}
	for _, name := range []string{"status", "info/fixture.list", "info/fixture.md5sums", "updates/0001", "triggers/Unincorp"} {
		t.Run(name, func(t *testing.T) {
			if e := os.MkdirAll(filepath.Dir(filepath.Join(d, name)), 0700); e != nil {
				t.Fatal(e)
			}
			prior, e := digest()
			if e != nil {
				t.Fatal(e)
			}
			write(name, "changed database-only content "+name)
			after, e := digest()
			if e != nil || after == prior {
				t.Fatalf("database change omitted: %v", e)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(d, "alias")
		if e := os.Symlink(filepath.Join(d, "status"), link); e != nil {
			t.Fatal(e)
		}
		defer os.Remove(link)
		if _, e := digest(); e != ErrGap {
			t.Fatal("database symlink accepted", e)
		}
	})
	limits.Bytes = 1
	if _, e := digest(); e != ErrGap {
		t.Fatal("database byte limit ignored", e)
	}
}

// Claim: native status translation only admits the exact dpkg terminal triple;
// installed-looking but held/error/partial states cannot hide behind a suffix.
func TestReconcileNativeStatus(t *testing.T) {
	for _, raw := range []string{"install ok installed", "hold ok installed", "install reinstreq installed", "deinstall ok installed", "install ok unpacked", "install ok half-installed", "install ok triggers-pending"} {
		status, pending := nativePackageStatus(raw)
		if raw == "install ok installed" {
			if status != "installed" || pending {
				t.Fatal(raw)
			}
		} else if !pending {
			t.Fatal("nonterminal state lost", raw)
		}
	}
}

// Claim: the pinned audit runner requires silent exit-zero, and changed tool
// bytes, nonzero exit and even exit-zero diagnostic output refuse. These owned
// command controls do not claim to exercise a live root dpkg database audit.
func TestReconcilePinnedAuditContract(t *testing.T) {
	ctx := context.Background()
	if e := runPinnedEmpty(ctx, toolFixture(t, "/usr/bin/true"), []string{}, 128, true); e != nil {
		t.Fatal("silent success control", e)
	}
	if e := runPinnedEmpty(ctx, toolFixture(t, "/usr/bin/false"), []string{}, 128, true); e != ErrGap {
		t.Fatal("failed audit accepted", e)
	}
	if e := runPinnedEmpty(ctx, toolFixture(t, "/usr/bin/printf"), []string{"dirty audit"}, 128, true); e != ErrGap {
		t.Fatal("dirty audit accepted", e)
	}
	pin := toolFixture(t, "/usr/bin/true")
	pin.SHA256 = Digest([]byte("other bytes"))
	if e := runPinnedEmpty(ctx, pin, nil, 128, true); e != ErrTool {
		t.Fatal("changed audit tool accepted", e)
	}
}
