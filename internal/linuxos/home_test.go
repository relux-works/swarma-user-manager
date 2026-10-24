//go:build linux

package linuxos

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testLimits() Limits { return Limits{Entries: 10000, Depth: 32, Duration: 5 * time.Second} }
func fixtureDir(t *testing.T, path string) *Dir {
	t.Helper()
	// Test-only anchor: bypass host workspace ownership, never production APIs.
	fd, e := unix.Openat2(unix.AT_FDCWD, filepath.Clean(path), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if e != nil {
		t.Fatal(e)
	}
	if e = unix.Fchown(fd, os.Getuid(), os.Getgid()); e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	if e = unix.Fchmod(fd, 0700); e != nil {
		unix.Close(fd)
		t.Fatal(e)
	}
	d := &Dir{f: os.NewFile(uintptr(fd), "fixture"), owner: uint32(os.Getuid()), group: uint32(os.Getgid())}
	t.Cleanup(func() {
		if e := d.Close(); e != nil {
			t.Error(e)
		}
	})
	return d
}
func fixtureManifest(t *testing.T) Manifest {
	t.Helper()
	m, e := stationManifest(uint32(os.Getuid()), uint32(os.Getgid()), []Control{{Path: "AGENTS.md", Data: []byte("approved-context\n")}, {Path: ".platform/trust-pin.json", Data: []byte("approved-pin\n")}, {Path: ".platform/skills/example.md", Data: []byte("approved-skill\n")}, {Path: ".harness/settings.json", Data: []byte("approved-settings\n")}}, uint32(os.Getuid()), uint32(os.Getgid()))
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func aclFor(uid uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, 2)
	for _, v := range [][3]uint32{{1, 7, ^uint32(0)}, {2, 5, uid}, {4, 0, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b[:2], uint16(v[0]))
		binary.LittleEndian.PutUint16(b[2:4], uint16(v[1]))
		binary.LittleEndian.PutUint32(b[4:], v[2])
		out = append(out, b...)
	}
	return out
}
func installFixture(t *testing.T) (string, *Dir, Manifest) {
	t.Helper()
	path := t.TempDir()
	parent := fixtureDir(t, path)
	m := fixtureManifest(t)
	stage, e := parent.Install(context.Background(), "home", m, testLimits())
	if e != nil {
		t.Fatal(stage, e)
	}
	home, e := parent.OpenDirectory("home")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { home.Close() })
	return filepath.Join(path, "home"), home, m
}

// Inherited default/access ACLs refuse before publication; no-ACL neighbor
// installs and verifies exact bytes/modes. Root:S ownership is a private runner
// mapping here, not a privileged ownership qualification.
func TestInstallerInheritedACLRefused(t *testing.T) {
	path := t.TempDir()
	parent := fixtureDir(t, path)
	uid := uint32(os.Getuid()) + 100000
	if e := unix.Setxattr(path, "system.posix_acl_default", aclFor(uid), 0); e != nil {
		t.Fatal(e)
	}
	if _, e := parent.Install(context.Background(), "home", fixtureManifest(t), testLimits()); errorCode(e) != "access_metadata_present" {
		t.Fatal("inherited ACL accepted")
	}
	if _, e := os.Lstat(filepath.Join(path, "home")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("home published after ACL refusal")
	}
	if e := unix.Removexattr(path, "system.posix_acl_default"); e != nil {
		t.Fatal(e)
	}
	if _, e := parent.Install(context.Background(), "home", fixtureManifest(t), testLimits()); e != nil {
		t.Fatal(e)
	}
}

// A no-follow exact walk rejects symlink aliases, extra/missing paths and
// unreadable descendant enumeration; restoring each change passes the neighbor.
func TestVerifierFailClosedWalk(t *testing.T) {
	path, home, m := installFixture(t)
	ctx := context.Background()
	if _, e := home.Verify(ctx, m, testLimits()); e != nil {
		t.Fatal(e)
	}
	control := filepath.Join(path, "AGENTS.md")
	bytes, e := os.ReadFile(control)
	if e != nil {
		t.Fatal(e)
	}
	outside := filepath.Join(t.TempDir(), "sentinel")
	if e = os.WriteFile(outside, []byte("outside"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(control); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(outside, control); e != nil {
		t.Fatal(e)
	}
	if _, e = home.Verify(ctx, m, testLimits()); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e = home.ReplaceManaged(ctx, m, "AGENTS.md"); e == nil {
		t.Fatal("replacement accepted symlink destination")
	}
	if got, _ := os.ReadFile(outside); string(got) != "outside" {
		t.Fatal("outside sentinel changed")
	}
	os.Remove(control)
	os.WriteFile(control, bytes, 0640)
	if _, e = home.Verify(ctx, m, testLimits()); e != nil {
		t.Fatal(e)
	}
	extra := filepath.Join(path, "work", "extra")
	os.WriteFile(extra, []byte("unexpected"), 0600)
	if _, e = home.Verify(ctx, m, testLimits()); e == nil {
		t.Fatal("extra accepted")
	}
	os.Remove(extra)
	os.Remove(control)
	if _, e = home.Verify(ctx, m, testLimits()); e == nil {
		t.Fatal("missing accepted")
	}
	os.WriteFile(control, bytes, 0640)
	leaf := filepath.Join(path, ".platform", "skills")
	t.Cleanup(func() {
		if e := unix.Chmod(leaf, 0750); e != nil && !errors.Is(e, unix.ENOENT) {
			t.Error(e)
		}
	})
	unix.Chmod(leaf, 0000)
	if _, e = home.Verify(ctx, m, testLimits()); e == nil {
		t.Fatal("incomplete walk accepted")
	}
	unix.Chmod(leaf, 0750)
	if _, e = home.Verify(ctx, m, testLimits()); e != nil {
		t.Fatal(e)
	}
}

// Atomic managed replacement changes the checked inode/digest; forged writable
// ancestry and unexpected ACL metadata refuse without modifying approved bytes.
func TestAtomicReplaceAndMetadataRefusal(t *testing.T) {
	path, home, m := installFixture(t)
	next := fixtureManifest(t)
	v := next.entries["AGENTS.md"]
	v.data = []byte("new approved context\n")
	next.entries["AGENTS.md"] = v
	if stage, e := home.ReplaceManaged(context.Background(), next, "AGENTS.md"); e != nil || stage != "" {
		t.Fatal(stage, e)
	}
	digest, e := home.Verify(context.Background(), next, testLimits())
	if e != nil {
		t.Fatal(e)
	}
	if digest["AGENTS.md"] != sha256.Sum256(v.data) {
		t.Fatal("digest not actual new bytes")
	}
	unix.Chmod(filepath.Join(path, ".platform"), 0770)
	if _, e = home.ReplaceManaged(context.Background(), m, ".platform/trust-pin.json"); e == nil {
		t.Fatal("writable parent accepted")
	}
	unix.Chmod(filepath.Join(path, ".platform"), 0750)
	file := filepath.Join(path, "AGENTS.md")
	if e = unix.Setxattr(file, "system.posix_acl_access", aclFor(uint32(os.Getuid())+100000), 0); e != nil {
		t.Fatal(e)
	}
	if e = unix.Chmod(file, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e = home.Verify(context.Background(), next, testLimits()); errorCode(e) != "access_metadata_present" {
		t.Fatal("stored ACL refusal missing", e)
	}
	unix.Removexattr(file, "system.posix_acl_access")
	unix.Chmod(file, 0640)
	if _, e = home.Verify(context.Background(), next, testLimits()); e != nil {
		t.Fatal(e)
	}
}

// A bounded deletion batch leaves explicit partial progress, then completes;
// a nested symlink is unlinked while its outside target and unrelated sibling survive.
func TestDeleteBoundedNoFollow(t *testing.T) {
	path := t.TempDir()
	parent := fixtureDir(t, path)
	home := filepath.Join(path, "home")
	os.Mkdir(home, 0700)
	os.Mkdir(filepath.Join(home, "nested"), 0700)
	for _, n := range []string{"a", "b", "c"} {
		os.WriteFile(filepath.Join(home, n), []byte("fixture"), 0600)
	}
	outside := filepath.Join(t.TempDir(), "keep")
	os.WriteFile(outside, []byte("sentinel"), 0600)
	os.Symlink(outside, filepath.Join(home, "nested", "link"))
	os.WriteFile(filepath.Join(path, "sibling"), []byte("sibling"), 0600)
	l := testLimits()
	l.Entries = 3
	first, e := parent.DeleteBatch(context.Background(), "home", l)
	if e != nil || first.Done || first.Visited > 3 {
		t.Fatal(first, e)
	}
	done := false
	for i := 0; i < 10; i++ {
		r, e := parent.DeleteBatch(context.Background(), "home", l)
		if e != nil {
			t.Fatal(e)
		}
		if r.Done {
			done = true
			break
		}
	}
	if !done {
		t.Fatal("no bounded progress")
	}
	if b, _ := os.ReadFile(outside); string(b) != "sentinel" {
		t.Fatal("followed symlink")
	}
	if b, _ := os.ReadFile(filepath.Join(path, "sibling")); string(b) != "sibling" {
		t.Fatal("deleted sibling")
	}
	if _, e = parent.DeleteBatch(context.Background(), "../sibling", l); e == nil {
		t.Fatal("escape accepted")
	}
}

func errorCode(e error) string {
	var typed *Error
	if errors.As(e, &typed) {
		return typed.Code
	}
	return ""
}

// The real anchor constructor refuses symlink components, and a shared sticky
// ancestor permits inventory but cannot authorize publication beneath it.
func TestRootAnchorNoFollowAndPublicationFence(t *testing.T) {
	d, e := OpenRoot("/tmp")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.protected(); e == nil {
		t.Fatal("shared temporary root authorized publication")
	}
	path, e := os.MkdirTemp("/tmp", "station-anchor-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(path, "alias")); os.Remove(path) })
	if e = os.Symlink("/tmp", filepath.Join(path, "alias")); e != nil {
		t.Fatal(e)
	}
	if x, e := OpenRoot(filepath.Join(path, "alias")); e == nil {
		x.Close()
		t.Fatal("symlink anchor accepted")
	}
}

// Descriptor descent retains publication distrust from a writable ancestor;
// a private nonwritable parent allows the otherwise identical child.
func TestDirectoryDescentRetainsPublicationFence(t *testing.T) {
	path := t.TempDir()
	parent := fixtureDir(t, path)
	if e := os.Mkdir(filepath.Join(path, "child"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := unix.Chmod(path, 01777); e != nil {
		t.Fatal(e)
	}
	child, e := parent.OpenDirectory("child")
	if e != nil {
		t.Fatal(e)
	}
	if e = child.protected(); errorCode(e) != "unsafe_ancestor" {
		t.Fatal("writable ancestor forgotten", e)
	}
	if e = child.Close(); e != nil {
		t.Fatal(e)
	}
	if e = unix.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	child, e = parent.OpenDirectory("child")
	if e != nil {
		t.Fatal(e)
	}
	defer child.Close()
	if e = child.protected(); e != nil {
		t.Fatal("private positive control refused", e)
	}
}

// An ACL on a held ancestor remains a refusal at both managed gates, even if
// the child metadata and bytes are valid; removing it and reopening passes.
func TestManagedGateRetainsAncestorFailures(t *testing.T) {
	path, _, m := installFixture(t)
	parentPath := filepath.Dir(path)
	parent := fixtureDir(t, parentPath)
	if e := unix.Setxattr(parentPath, "system.posix_acl_default", aclFor(uint32(os.Getuid())+100000), 0); e != nil {
		t.Fatal(e)
	}
	home, e := parent.OpenDirectory("home")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = home.Verify(context.Background(), m, testLimits()); errorCode(e) != "access_metadata_present" {
		t.Fatal("ancestor ACL forgotten", e)
	}
	if _, e = home.ReplaceManaged(context.Background(), m, "AGENTS.md"); errorCode(e) != "access_metadata_present" {
		t.Fatal("replacement lost ancestor ACL", e)
	}
	if e = home.Close(); e != nil {
		t.Fatal(e)
	}
	if e = unix.Removexattr(parentPath, "system.posix_acl_default"); e != nil {
		t.Fatal(e)
	}
	home, e = parent.OpenDirectory("home")
	if e != nil {
		t.Fatal(e)
	}
	defer home.Close()
	if _, e = home.Verify(context.Background(), m, testLimits()); e != nil {
		t.Fatal("clean ancestor refused", e)
	}
}
