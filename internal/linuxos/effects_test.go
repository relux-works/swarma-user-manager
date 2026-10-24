//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Names are derived before I/O; collisions and invalid keys never adopt or
// overwrite a stage. Observation reports links without following their target.
func TestEffectNamesAndUnreceiptedStageHeld(t *testing.T) {
	d := fixtureDir(t, t.TempDir())
	stage, q, err := EffectNames(testEffectKey)
	if err != nil || stage != "stage-"+testEffectKey || q != "q-"+testEffectKey {
		t.Fatal(stage, q, err)
	}
	for _, bad := range []string{"", "../bad", testEffectKey[:63], "ABCDEF" + testEffectKey[6:]} {
		if _, _, err = EffectNames(bad); err == nil {
			t.Fatal("invalid key accepted")
		}
	}
	if err = unix.Mkdirat(int(d.f.Fd()), stage, 0700); err != nil {
		t.Fatal(err)
	}
	before, err := d.Observe(context.Background(), stage, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateStage(context.Background(), testEffectKey); err == nil {
		t.Fatal("unreceipted stage adopted")
	}
	after, err := d.Observe(context.Background(), stage, 1024)
	if err != nil || after != before {
		t.Fatal("foreign stage changed")
	}
	if err = unix.Symlinkat("/unreadable-target-never-followed", int(d.f.Fd()), "link"); err != nil {
		t.Fatal(err)
	}
	link, err := d.Observe(context.Background(), "link", 1024)
	if err != nil || link.Type != "symlink" || link.Digest != "" {
		t.Fatal("link followed/unobserved", err)
	}
}

// A live exclusively created handle plus matching receipt permits a no-replace
// move preserving inode. Wrong receipts and destination collisions leave both
// entries intact. This is not restart/inode-reuse qualification.
func TestOwnedStagePublication(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	stage, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if _, err = d.CreateStage(ctx, testEffectKey); err == nil {
		t.Fatal("stage collision accepted")
	}
	receipt := stage.Identity()
	bad := receipt
	bad.Inode++
	if _, err = stage.Publish(ctx, d, "home", bad); err == nil {
		t.Fatal("wrong receipt accepted")
	}
	if err = os.WriteFile(filepath.Join(path, "home"), []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = stage.Publish(ctx, d, "home", receipt); err == nil {
		t.Fatal("foreign destination overwritten")
	}
	b, _ := os.ReadFile(filepath.Join(path, "home"))
	if string(b) != "foreign" {
		t.Fatal("foreign bytes changed")
	}
	if err = os.Remove(filepath.Join(path, "home")); err != nil {
		t.Fatal(err)
	}
	got, err := stage.Publish(ctx, d, "home", receipt)
	if err != nil || got.Inode != receipt.Inode || got.Device != receipt.Device {
		t.Fatal("owned move lost identity", err)
	}
	if _, err = stage.Publish(ctx, d, "other", receipt); err == nil {
		t.Fatal("stale source reused")
	}
}

// Approved stage population returns exact checked file digests/metadata; a
// changed regular file or extra path cannot satisfy the original manifest.
func TestEffectManagedStageObservation(t *testing.T) {
	d := fixtureDir(t, t.TempDir())
	ctx := context.Background()
	stage, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	m := fixtureManifest(t)
	objects, err := stage.Populate(ctx, stage.Identity(), m, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(m.entries["AGENTS.md"].data)
	if objects["AGENTS.md"].Digest != hex.EncodeToString(sum[:]) {
		t.Fatal("digest missing")
	}
	home := stage.Identity()
	if home.Mode != 0750 || home.UID != uint32(os.Getuid()) {
		t.Fatal("home metadata")
	}
	if _, err = stage.Populate(ctx, home, m, testLimits()); err == nil {
		t.Fatal("nonempty stage reinstalled")
	}
	if _, err = stage.Publish(ctx, d, "home", home); err != nil {
		t.Fatal(err)
	}
}

// Public quarantine requires root before mutation; observing an unproved object
// confers no move/release token and leaves it byte-for-byte intact.
func TestUnprovedQuarantineIsLogical(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(path, "foreign"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := d.Observe(ctx, "foreign", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err = (*OwnedStage)(nil).Quarantine(ctx, d, testEffectKey, before); errorCode(err) != "root_required" {
			t.Fatal("quarantine root gate", err)
		}
	}
	after, err := d.Observe(ctx, "foreign", 1024)
	if err != nil || after != before {
		t.Fatal("unproved object mutated")
	}
	var zero OwnedStage
	if _, err = zero.Publish(ctx, d, "adopted", before); err == nil {
		t.Fatal("observed identity became ownership")
	}
}

// A replacement at the deterministic source name is not the live owned inode;
// no replacement is moved. Empty destination directories also must not be
// overwritten (unlike nonempty/type-mismatched destinations, they test NOREPLACE).
func TestPublishedHomeReplacementRefused(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	ctx := context.Background()
	s, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	receipt := s.Identity()
	if err = unix.Mkdirat(int(d.f.Fd()), "foreign-empty", 0700); err != nil {
		t.Fatal(err)
	}
	before, err := d.Observe(ctx, "foreign-empty", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish(ctx, d, "foreign-empty", receipt); err == nil {
		t.Fatal("empty foreign destination overwritten")
	}
	after, err := d.Observe(ctx, "foreign-empty", 1)
	if err != nil || after != before {
		t.Fatal("foreign destination identity changed")
	}
	stage, _, _ := EffectNames(testEffectKey)
	if err = unix.Renameat(int(d.f.Fd()), stage, int(d.f.Fd()), "held-original"); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mkdirat(int(d.f.Fd()), stage, 0700); err != nil {
		t.Fatal(err)
	}
	foreign, err := d.Observe(ctx, stage, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish(ctx, d, "home", receipt); err == nil {
		t.Fatal("replaced source adopted")
	}
	now, err := d.Observe(ctx, stage, 1)
	if err != nil || now != foreign {
		t.Fatal("replacement changed")
	}
}

// The same rename mechanism used behind the root-only quarantine entry preserves
// the owned inode across home->q and does not copy across filesystems. Exercising
// this private mechanism as the runner does not qualify root admission itself.
func TestOwnedQuarantineRenameMechanism(t *testing.T) {
	d := fixtureDir(t, t.TempDir())
	q := fixtureDir(t, t.TempDir())
	ctx := context.Background()
	s, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	receipt := s.Identity()
	if _, err = s.Publish(ctx, d, "home", receipt); err != nil {
		t.Fatal(err)
	}
	_, name, _ := EffectNames(testEffectKey)
	moved, err := s.move(ctx, q, name, receipt, "quarantined")
	if err != nil || moved.Inode != receipt.Inode || moved.Device != receipt.Device {
		t.Fatal("quarantine mechanism identity", err)
	}
	if _, err = d.Observe(ctx, "home", 1); !os.IsNotExist(err) {
		t.Fatal("home source not absent", err)
	}
	if _, err = s.Publish(ctx, d, "released", receipt); err == nil {
		t.Fatal("quarantine automatically released")
	}
}

// A real different-device destination is refused without source removal or
// destination creation; this uses only task-owned directories, never mounts.
func TestEffectCrossFilesystemRefused(t *testing.T) {
	path, err := os.MkdirTemp("/dev/shm", "station-effect-test-")
	if err != nil {
		t.Skip("PENDING: no writable separate filesystem", err)
	}
	defer os.Remove(path)
	to := fixtureDir(t, path)
	d := fixtureDir(t, t.TempDir())
	ctx := context.Background()
	s, err := d.CreateStage(ctx, testEffectKey)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	dest, err := descriptorStat(to.f)
	if err != nil {
		t.Fatal(err)
	}
	receipt := s.Identity()
	if uint64(dest.Dev) == receipt.Device {
		t.Skip("PENDING: fixture filesystems share device")
	}
	if _, err = s.Publish(ctx, to, "home", receipt); errorCode(err) != "cross_device" {
		t.Fatal("cross-device not explicitly refused", err)
	}
	if _, err = to.Observe(ctx, "home", 1); !os.IsNotExist(err) {
		t.Fatal("cross-device destination created", err)
	}
	if err = s.validate(ctx, receipt); err != nil {
		t.Fatal("source changed", err)
	}
}

// Real peer-owned bytes are observed through a descriptor, with distinct peer
// UID and exact digest; observing ownership never grants a mutation token.
func TestPeerReceiptObservation(t *testing.T) {
	a, b := peerUID(t, "platform-test-a"), peerUID(t, "platform-test-b")
	if a == b {
		t.Fatal("peer identities overlap")
	}
	path := t.TempDir()
	d := fixtureDir(t, path)
	// Parent ancestors of Go test fixtures are private; place only this peer fixture
	// in /tmp, owned by the test runner with sticky traversal and exact cleanup.
	peerPath, err := os.MkdirTemp("/tmp", "station-receipt-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(peerPath)
	peerDir := fixtureDir(t, peerPath)
	if err = unix.Chmod(peerPath, 01777); err != nil {
		t.Fatal(err)
	}
	peerRun(t, "platform-test-a", "open('peer-file','xb').write(b'peer receipt fixture')", peerPath)
	observed, err := peerDir.Observe(context.Background(), "peer-file", 1024)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("peer receipt fixture"))
	if observed.UID != a || observed.UID == b || observed.Digest != hex.EncodeToString(digest[:]) || observed.Type != "regular" {
		t.Fatal("peer observation mismatch")
	}
	if _, err = (*OwnedStage)(nil).Publish(context.Background(), d, "adopted", observed); err == nil {
		t.Fatal("peer observation became ownership")
	}
}
