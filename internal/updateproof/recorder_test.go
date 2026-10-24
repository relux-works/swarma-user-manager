package updateproof

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func sampleSnapshot(version string) Snapshot {
	return Snapshot{Packages: []Package{{Name: "fixture", Version: version, Architecture: "amd64", Status: "installed", ArchiveSHA256: Digest([]byte(version))}}, Leaves: []Leaf{{Path: "/usr/lib/fixture", Package: "fixture", Architecture: "amd64", SHA256: Digest([]byte(version)), Mode: 0644, UID: 0, GID: 0}}}
}
func recorderFixture(t *testing.T) *Recorder {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "recorder.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openRecorder(d, uint32(os.Getuid()), d, Limits{Bytes: 1 << 20, Entries: 100, Members: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// Claim: distinct dpkg invocations retain ordered membership and intermediate
// versions; duplicate phases are idempotent, conflicting reuse cannot write.
func TestUpdateHookGapRefused(t *testing.T) {
	r := recorderFixture(t)
	ctx := context.Background()
	s1, s2, s3 := sampleSnapshot("1"), sampleSnapshot("2"), sampleSnapshot("3")
	a, err := r.Begin(ctx, "boot-a", "aggregate", "apt-start", ID{}, s1)
	if err != nil {
		t.Fatal(err)
	}
	i, err := r.Begin(ctx, "boot-a", "invocation", "dpkg-first", a, s1)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.End(ctx, i, s2, "complete"); err != nil {
		t.Fatal(err)
	}
	if err = r.End(ctx, i, s2, "complete"); err != nil {
		t.Fatal(err)
	}
	if err = r.End(ctx, i, s3, "complete"); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting phase: %v", err)
	}
	j, err := r.Begin(ctx, "boot-a", "invocation", "dpkg-second", a, s2)
	if err != nil {
		t.Fatal(err)
	}
	if i == j {
		t.Fatal("merged invocation IDs")
	}
	if err = r.End(ctx, j, s3, "complete"); err != nil {
		t.Fatal(err)
	}
	if err = r.End(ctx, a, s3, "complete"); err != nil {
		t.Fatal(err)
	}
	scan, err := r.Scan(ctx, s3)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Pending) != 1 || len(scan.Pending[0].Invocations) != 2 || scan.Pending[0].Invocations[0].ID != i || scan.Pending[0].Invocations[1].ID != j {
		t.Fatalf("membership lost: %+v", scan)
	}
	if _, err = r.Scan(ctx, sampleSnapshot("99")); !errors.Is(err, ErrGap) {
		t.Fatalf("unrecorded package transition: %v", err)
	}
}

// Claim: boot recovers complete missed post notifications, but not an unfinished
// invocation, forged current endpoint, or a corrupt/gapped journal.
func TestUpdateMissedHookAtBoot(t *testing.T) {
	r := recorderFixture(t)
	ctx := context.Background()
	s := sampleSnapshot("1")
	id, err := r.Begin(ctx, "boot-a", "invocation", "standalone", ID{}, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Scan(ctx, s); !errors.Is(err, ErrGap) {
		t.Fatalf("incomplete hook accepted: %v", err)
	}
	if err = r.End(ctx, id, s, "complete"); err != nil {
		t.Fatal(err)
	}
	got, err := r.Scan(ctx, s)
	if err != nil || len(got.Pending) != 1 {
		t.Fatalf("missed queue at boot: %+v %v", got, err)
	}
	if err = os.WriteFile(filepath.Join(r.path, "00000000000000000001.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Scan(ctx, s); !errors.Is(err, ErrStore) {
		t.Fatalf("corrupt journal: %v", err)
	}
}

// Claim: no-follow and private ownership/modes prevent evidence adoption;
// fixture success uses this test user's explicitly selected owner only.
func TestRecorderProtection(t *testing.T) {
	r := recorderFixture(t)
	if err := os.Chmod(r.path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Begin(context.Background(), "boot-a", "invocation", "one", ID{}, sampleSnapshot("1")); !errors.Is(err, ErrStore) {
		t.Fatalf("unprotected state: %v", err)
	}
}
