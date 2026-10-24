//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Closing an owned listener preserves its socket inode. The local check must
// still work without a connection, while the full metadata probe refuses it.
// This proves no connect probe, not provider liveness or stream completion.
func TestSystemdNamespaceDoesNotConnect(t *testing.T) {
	f := newSystemdFixture(t)
	before, e := f.runtime.LocalNamespaceFingerprint(context.Background(), testLimits())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.capture(); e != nil {
		t.Fatal("listening control", e)
	}
	if e = f.listeners["io.systemd.DynamicUser"].Close(); e != nil {
		t.Fatal(e)
	}
	after, e := f.runtime.LocalNamespaceFingerprint(context.Background(), testLimits())
	if e != nil || before != after {
		t.Fatal("local check connected or changed stable socket", e)
	}
	if _, e = f.capture(); errorCode(e) != "directory_unknown" || !errors.Is(e, unix.ECONNREFUSED) {
		t.Fatal("full probe did not detect closed listener", e)
	}
}

// A local or metadata-only observation cannot masquerade as a successful full
// capture. Absent/empty states and the traversal budget are checked locally too.
func TestSystemdNamespaceLocalChecks(t *testing.T) {
	f := newSystemdFixture(t)
	if _, e := f.runtime.LocalNamespaceFingerprint(context.Background(), testLimits()); e != nil {
		t.Fatal("valid local", e)
	}
	if _, e := f.capture(); e != nil {
		t.Fatal("valid metadata", e)
	}
	if fp, e := f.runtime.CapturedNamespaceFingerprint(); errorCode(e) != "directory_unknown" || fp != "" {
		t.Fatal("metadata became full evidence", fp, e)
	}
	if e := os.Mkdir(filepath.Join(f.root, "etc/userdb"), 0700); e != nil {
		t.Fatal(e)
	}
	if fp, e := f.runtime.LocalNamespaceFingerprint(context.Background(), testLimits()); errorCode(e) != "directory_unknown" || fp != "" {
		t.Fatal("absent-to-empty state accepted", fp, e)
	}
	f.manifest.Directories[0].State = "empty"
	f.writeManifest(t)
	if _, e := f.runtime.LocalNamespaceFingerprint(context.Background(), testLimits()); e != nil {
		t.Fatal("recorded empty control", e)
	}
	l := testLimits()
	l.Depth = 1
	if fp, e := f.runtime.LocalNamespaceFingerprint(context.Background(), l); errorCode(e) != "directory_unknown" || fp != "" {
		t.Fatal("depth budget ignored", fp, e)
	}
}

// These bounded perturbations state the inherited namespace comparison contract:
// bind all stableStat endpoint fields, directory identity/protection, path and
// manifest; ignore atime and unrelated directory timestamps/link/size changes.
func TestSystemdNamespaceFingerprintFields(t *testing.T) {
	for _, directory := range []bool{false, true} {
		kind := "socket"
		mode := uint32(unix.S_IFSOCK | 0600)
		if directory {
			kind = "directory"
			mode = unix.S_IFDIR | 0700
		}
		t.Run(kind, func(t *testing.T) {
			base := unix.Stat_t{Dev: 1, Ino: 2, Mode: mode, Uid: 3, Gid: 4, Nlink: 1, Size: 5, Mtim: unix.Timespec{Sec: 6}, Ctim: unix.Timespec{Sec: 7}}
			for _, field := range []string{"unchanged", "dev", "ino", "mode", "uid", "gid", "type", "nlink", "size", "mtime", "ctime", "atime", "path", "manifest"} {
				t.Run(field, func(t *testing.T) {
					next := base
					path, manifest := "/qualified/object", "manifest"
					wantSame := field == "unchanged" || field == "atime" || directory && (field == "nlink" || field == "size" || field == "mtime" || field == "ctime")
					switch field {
					case "dev":
						next.Dev++
					case "ino":
						next.Ino++
					case "mode":
						next.Mode ^= 0001
					case "uid":
						next.Uid++
					case "gid":
						next.Gid++
					case "type":
						next.Mode = unix.S_IFREG | 0600
					case "nlink":
						next.Nlink++
					case "size":
						next.Size++
					case "mtime":
						next.Mtim.Nsec++
					case "ctime":
						next.Ctim.Nsec++
					case "atime":
						next.Atim.Nsec++
					case "path":
						path += "-other"
					case "manifest":
						manifest += "-other"
					}
					before := namespaceFingerprint("manifest", map[string]unix.Stat_t{"/qualified/object": base})
					after := namespaceFingerprint(manifest, map[string]unix.Stat_t{path: next})
					if (before == after) != wantSame {
						t.Fatal("namespace binding", field, wantSame)
					}
					if field != "path" && field != "manifest" && sameUserDBObject(base, next) != wantSame {
						t.Fatal("landed comparison differs from stated field contract", field)
					}
				})
			}
		})
	}
}
