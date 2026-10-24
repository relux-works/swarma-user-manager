package updateproof

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// Claim: an in-process post hook cannot certify terminal success; its identical
// duplicate is harmless, conflicting evidence refuses, and a separate terminal
// observation is required before boot can enqueue a complete invocation.
func TestUpdatePostHookIsNotTerminal(t *testing.T) {
	r := recorderFixture(t)
	ctx := context.Background()
	s := sampleSnapshot("1")
	id, e := r.Begin(ctx, "boot-a", "invocation", "post-observation", ID{}, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.ObservePost(ctx, id, s); e != nil {
		t.Fatal(e)
	}
	if e = r.ObservePost(ctx, id, s); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Scan(ctx, s); e != ErrGap {
		t.Fatalf("post hook manufactured exit: %v", e)
	}
	if e = r.ObservePost(ctx, id, sampleSnapshot("2")); e != ErrConflict {
		t.Fatalf("conflicting post event: %v", e)
	}
	if e = r.End(ctx, id, s, "complete"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Scan(ctx, s); e != nil {
		t.Fatal(e)
	}
}

// Claim: renaming away the protected directory cannot redirect durable evidence
// into a detached inode while a replacement path appears to be current state.
func TestRecorderDirectoryReplacementRefused(t *testing.T) {
	r := recorderFixture(t)
	old := r.path + "-detached"
	if e := os.Rename(r.path, old); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(old) })
	if e := os.Mkdir(r.path, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Begin(context.Background(), "boot-a", "invocation", "replaced", ID{}, sampleSnapshot("1")); e != ErrStore {
		t.Fatalf("detached evidence accepted: %v", e)
	}
}

// Claim: retry deduplication binds complete begin bytes, symlinks cannot be
// adopted as events, and a saturated recorder cannot claim terminal completion.
func TestRecorderConflictSymlinkAndSaturation(t *testing.T) {
	t.Run("begin-conflict", func(t *testing.T) {
		r := recorderFixture(t)
		ctx := context.Background()
		s := sampleSnapshot("1")
		id, e := r.Begin(ctx, "boot-a", "invocation", "retry", ID{}, s)
		if e != nil {
			t.Fatal(e)
		}
		again, e := r.Begin(ctx, "boot-a", "invocation", "retry", ID{}, s)
		if e != nil || again != id {
			t.Fatal("non-idempotent retry", e)
		}
		if _, e = r.Begin(ctx, "boot-a", "invocation", "retry", ID{}, sampleSnapshot("2")); e != ErrConflict {
			t.Fatal("conflicting begin", e)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		r := recorderFixture(t)
		victim := filepath.Join(t.TempDir(), "untouched")
		if e := os.WriteFile(victim, []byte("keep"), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink(victim, filepath.Join(r.path, "00000000000000000001.json")); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Scan(context.Background(), sampleSnapshot("1")); e != ErrStore {
			t.Fatal("symlink evidence adopted", e)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Fatal("victim changed")
		}
	})
	t.Run("saturation", func(t *testing.T) {
		r := recorderFixture(t)
		r.limits.Entries = 1
		ctx := context.Background()
		s := sampleSnapshot("1")
		id, e := r.Begin(ctx, "boot-a", "invocation", "saturated", ID{}, s)
		if e != nil {
			t.Fatal(e)
		}
		if e = r.End(ctx, id, s, "complete"); e != ErrStore {
			t.Fatal("saturation completed", e)
		}
		if _, e = r.Scan(ctx, s); e != ErrGap {
			t.Fatal("incomplete accepted", e)
		}
	})
}

// Claim: separate recorder handles serialize on the same installed lock; a
// timed-out contender writes nothing and can succeed after the owner releases.
func TestRecorderCrossHandleExclusion(t *testing.T) {
	r := recorderFixture(t)
	other, e := openRecorder(r.path, uint32(os.Getuid()), r.path, r.limits)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	unlock, e := r.lock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, e := other.Begin(ctx, "boot-a", "invocation", "contender", ID{}, sampleSnapshot("1"))
		result <- e
	}()
	err := <-result
	unlock()
	if err != ErrStore {
		t.Fatal("contender did not refuse", err)
	}
	id, e := other.Begin(context.Background(), "boot-a", "invocation", "contender", ID{}, sampleSnapshot("1"))
	if e != nil || id.Sequence != 1 {
		t.Fatal("failed contender wrote/blocked state", id, e)
	}
}

// Claim: the captured checksum view selects exactly one complete entry; missing,
// malformed and duplicate attribution cannot substitute for the mapped leaf.
func TestUpdateCapturedChecksumEntry(t *testing.T) {
	entry := "0123456789abcdef0123456789abcdef"
	if got, e := checksumEntry([]byte(entry+"  usr/lib/fixture\n"), "usr/lib/fixture", 32); e != nil || got != entry {
		t.Fatal("checksum control", got, e)
	}
	for _, b := range []string{entry + "  usr/lib/other\n", entry + "  usr/lib/fixture\n" + entry + "  usr/lib/fixture\n", "bad  usr/lib/fixture\n"} {
		if _, e := checksumEntry([]byte(b), "usr/lib/fixture", 32); e != ErrChecksum {
			t.Fatal("ambiguous checksum", e)
		}
	}
}

// Claim: a complete event left visible by a sync failure is not durable evidence
// until recovery actually syncs it and its directory; retries do not duplicate
// the terminal event. This injects I/O acknowledgement failure, not power loss.
func TestRecorderSyncFailureCannotAcknowledge(t *testing.T) {
	r := recorderFixture(t)
	ctx := context.Background()
	s := sampleSnapshot("1")
	id, e := r.Begin(ctx, "boot-a", "invocation", "sync-failure", ID{}, s)
	if e != nil {
		t.Fatal(e)
	}
	r.syncFile = func(f *os.File) error {
		if f.Name() == "event" || filepath.Base(f.Name()) == "00000000000000000002.json" {
			return os.ErrPermission
		}
		return f.Sync()
	}
	if e = r.End(ctx, id, s, "complete"); e != ErrStore {
		t.Fatal("failed sync acknowledged", e)
	}
	if _, e = r.Scan(ctx, s); e != ErrStore {
		t.Fatal("unsynced terminal event accepted", e)
	}
	r.syncFile = (*os.File).Sync
	if e = r.End(ctx, id, s, "complete"); e != nil {
		t.Fatal("durable retry", e)
	}
	if got, e := r.Scan(ctx, s); e != nil || len(got.Pending) != 1 {
		t.Fatal("recovery queue", got, e)
	}
	entries, e := os.ReadDir(r.path)
	if e != nil || len(entries) != 3 {
		t.Fatal("duplicate retry effect", e, len(entries))
	}
}
