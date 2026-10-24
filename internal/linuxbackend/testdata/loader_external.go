package linuxos_test

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

type loaderFixture struct {
	root, early, late, defaults string
	reader                      linuxos.PathReader
	cache                       []byte
}

func newLoaderFixture(t *testing.T) loaderFixture {
	t.Helper()
	root := t.TempDir()
	reader := linuxos.QualificationLoaderReader(t, root)
	f := loaderFixture{root: root, early: filepath.Join(root, "early"), late: filepath.Join(root, "late"), defaults: filepath.Join(root, "defaults"), reader: reader, cache: make([]byte, 48)}
	for _, p := range []string{f.early, f.late, f.defaults} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	copy(f.cache, "glibc-ld.so.cache1.1")
	f.cache[28] = 2
	binary.LittleEndian.PutUint32(f.cache[24:28], 0)
	return f
}
func (f loaderFixture) resolver(t *testing.T, records []linuxbackend.ELFResolution) *linuxbackend.QualificationLoader {
	t.Helper()
	q := linuxbackend.QualificationLoaderNew(f.reader, []string{f.defaults}, f.cache, records)
	t.Cleanup(q.Close)
	return q
}
func loaderELF(t *testing.T, path, source string, flags ...string) {
	t.Helper()
	src := path + ".c"
	if e := os.WriteFile(src, []byte(source), 0600); e != nil {
		t.Fatal(e)
	}
	args := append([]string{"-shared", "-fPIC", "-nostdlib", "-o", path, src}, flags...)
	if out, e := exec.Command("/usr/bin/cc", args...).CombinedOutput(); e != nil {
		t.Fatalf("ELF fixture: %v %s", e, out)
	}
	if e := os.Chmod(path, 0755); e != nil {
		t.Fatal(e)
	}
}
func loaderLimits() linuxos.Limits {
	return linuxos.Limits{Entries: 10000, Depth: 32, Duration: 10 * time.Second}
}

// Every consulted location through the hit is recorded in order. Removing an
// earlier miss, planting an earlier same-name member, or adding hwcaps refuses
// through local revalidation and lookup; unchanged evidence is the control.
func TestLoaderProductionOrderedEvidence(t *testing.T) {
	for _, mode := range []string{"omitted", "plant", "hwcaps", "valid"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			loaderELF(t, filepath.Join(f.late, "dep.so"), "int dep(void){return 1;}")
			q := f.resolver(t, nil)
			rp := []string{f.early, f.late}
			record, e := q.Observe(ctx, "dep.so", rp)
			if e != nil {
				t.Fatal(e)
			}
			want := []linuxbackend.ELFSearchLocation{}
			for _, dir := range rp {
				want = append(want, linuxbackend.ELFSearchLocation{Kind: "hwcaps", Path: filepath.Join(dir, "glibc-hwcaps"), State: "absent", Resolved: filepath.Join(dir, "glibc-hwcaps"), Links: []linuxos.PathLink{}})
				loc := linuxbackend.ELFSearchLocation{Kind: "runpath", Path: filepath.Join(dir, "dep.so"), State: "absent", Resolved: filepath.Join(dir, "dep.so"), Links: []linuxos.PathLink{}}
				if dir == f.late {
					loc.State = "present"
					raw, e := os.ReadFile(loc.Path)
					if e != nil {
						t.Fatal(e)
					}
					loc.Digest = qualification.Hash(raw)
				}
				want = append(want, loc)
			}
			if !reflect.DeepEqual(record.Locations, want) {
				t.Fatalf("missing/reordered lookup evidence: got %#v want %#v", record.Locations, want)
			}
			if mode == "omitted" {
				record.Locations = append(record.Locations[:1], record.Locations[2:]...)
			}
			pinned := f.resolver(t, []linuxbackend.ELFResolution{record})
			if mode != "omitted" {
				if e = pinned.Revalidate(ctx); e != nil {
					t.Fatal("unchanged control", e)
				}
			}
			switch mode {
			case "plant":
				loaderELF(t, filepath.Join(f.early, "dep.so"), "int dep(void){return 2;}")
			case "hwcaps":
				if e = os.Mkdir(filepath.Join(f.early, "glibc-hwcaps"), 0700); e != nil {
					t.Fatal(e)
				}
			}
			local := pinned.Revalidate(ctx)
			a, lookup := pinned.ResolveELF(ctx, "dep.so", rp)
			if mode == "valid" {
				if local != nil || lookup != nil || a.Path != record.Path {
					t.Fatal("valid refused", local, lookup)
				}
			} else if !errors.Is(local, qualification.ErrRequired) || !errors.Is(lookup, qualification.ErrRequired) || a.Directory != nil {
				t.Fatal("drift returned authority", local, lookup, a)
			}
		})
	}
}

// RUNPATH belongs only to its carrying object's DT_NEEDED. A grandchild found
// only in the root's RUNPATH refuses; an explicit default or child's own RUNPATH
// provides nearby valid controls through the same production traversal.
func TestLoaderProductionRunpathNotInherited(t *testing.T) {
	for _, mode := range []string{"parent-only", "default", "default-duplicate", "child-own"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			loaderELF(t, filepath.Join(f.late, "grand.so"), "int grand(void){return 1;}")
			flags := []string{"-L" + f.late, "-Wl,--no-as-needed", "-l:grand.so"}
			if mode == "child-own" {
				flags = append(flags, "-Wl,--enable-new-dtags,-rpath,"+f.late)
			}
			loaderELF(t, filepath.Join(f.late, "child.so"), "extern int grand(void); int child(void){return grand();}", flags...)
			root := filepath.Join(f.root, "root.so")
			rootRunpath := f.late
			if mode == "default-duplicate" {
				rootRunpath += ":" + f.late
			}
			loaderELF(t, root, "extern int child(void); int root(void){return child();}", "-L"+f.late, "-Wl,--no-as-needed", "-l:child.so", "-Wl,--enable-new-dtags,-rpath,"+rootRunpath)
			if mode == "default" || mode == "default-duplicate" {
				raw, e := os.ReadFile(filepath.Join(f.late, "grand.so"))
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(f.defaults, "grand.so"), raw, 0755); e != nil {
					t.Fatal(e)
				}
			}
			a, e := f.reader.OpenArtifact(ctx, root)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Directory.Close()
			profile, files, digest, e := f.resolver(t, nil).Capture(ctx, []linuxos.ProtectedArtifact{a}, loaderLimits())
			if mode == "parent-only" {
				if !errors.Is(e, qualification.ErrRequired) || files != nil || digest != "" {
					t.Fatal("parent RUNPATH inherited", files, digest, e)
				}
				return
			}
			if e != nil || len(files) != 3 || digest == "" {
				t.Fatal("valid scope refused", files, e)
			}
			for _, record := range profile.Resolutions {
				if record.Name == "child.so" && !reflect.DeepEqual(record.Runpath, []string{f.late}) {
					t.Fatal("root RUNPATH not deduplicated", record.Runpath)
				}
			}
			pinned := f.resolver(t, profile.Resolutions)
			if e = pinned.Revalidate(ctx); e != nil {
				t.Fatal(e)
			}
			_, again, e := linuxos.CaptureImplementationClosure(ctx, []linuxos.ProtectedArtifact{a}, pinned, loaderLimits())
			if e != nil || again != digest {
				t.Fatal("exact scope replay", again, e)
			}
		})
	}
}

// Unrelated large files and ACL metadata cannot influence a name-scoped lookup.
// Actual member changes, canonical-link retargeting and missing reviewed records
// refuse, with an unchanged file as the positive control.
func TestLoaderProductionMemberIsolation(t *testing.T) {
	for _, mode := range []string{"member-bytes", "alias", "unknown-scope", "unrelated"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			target := filepath.Join(f.late, "actual.so")
			loaderELF(t, target, "int dep(void){return 1;}")
			alias := filepath.Join(f.late, "dep.so")
			if e := os.Symlink("actual.so", alias); e != nil {
				t.Fatal(e)
			}
			rp := []string{f.late}
			record, e := f.resolver(t, nil).Observe(ctx, "dep.so", rp)
			if e != nil {
				t.Fatal(e)
			}
			if len(record.Locations) != 2 || len(record.Locations[1].Links) != 1 || record.Locations[1].Links[0].Target != "actual.so" {
				t.Fatal("link chain omitted", record)
			}
			q := f.resolver(t, []linuxbackend.ELFResolution{record})
			if e = q.Revalidate(ctx); e != nil {
				t.Fatal("positive", e)
			}
			switch mode {
			case "member-bytes":
				file, e := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = file.Write([]byte("changed"))
				file.Close()
				if e != nil {
					t.Fatal(e)
				}
			case "alias":
				raw, e := os.ReadFile(target)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(f.late, "other.so"), raw, 0755); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(alias); e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink("other.so", alias); e != nil {
					t.Fatal(e)
				}
			case "unknown-scope":
				rp = []string{f.early, f.late}
			case "unrelated":
				file, e := os.OpenFile(filepath.Join(f.late, "unrelated-large"), os.O_CREATE|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				e = file.Truncate(128 << 20)
				file.Close()
				if e != nil {
					t.Fatal(e)
				}
				if e = unix.Setxattr(filepath.Join(f.late, "unrelated-large"), "system.posix_acl_access", loaderFixtureACL(uint32(os.Getuid()+1)), 0); e != nil {
					t.Fatal(e)
				}
				// A sibling symlink is never followed, even outside the approved anchor.
				if e = os.Symlink("/unreviewed/unrelated", filepath.Join(f.late, "unrelated-link")); e != nil {
					t.Fatal(e)
				}
			}
			a, e := q.ResolveELF(ctx, "dep.so", rp)
			if mode == "unrelated" {
				if e != nil || a.Path != record.Path || q.Revalidate(ctx) != nil {
					t.Fatal("unrelated names changed closure", e)
				}
			} else if !errors.Is(e, qualification.ErrRequired) || a.Directory != nil {
				t.Fatal("changed/unknown member admitted", a, e)
			}
		})
	}
}

func loaderFixtureACL(uid uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, 2)
	for _, v := range [][3]uint32{{1, 6, ^uint32(0)}, {2, 4, uid}, {4, 0, ^uint32(0)}, {16, 4, ^uint32(0)}, {32, 0, ^uint32(0)}} {
		row := make([]byte, 8)
		binary.LittleEndian.PutUint16(row, uint16(v[0]))
		binary.LittleEndian.PutUint16(row[2:], uint16(v[1]))
		binary.LittleEndian.PutUint32(row[4:], v[2])
		out = append(out, row...)
	}
	return out
}

// RUNPATH precedes cache; genuine cache miss uses reviewed defaults in order.
// An earlier default plant changes stored evidence. A stale selected cache entry
// refuses rather than silently broadening the supported fallback model.
func TestLoaderProductionCacheAndDefaults(t *testing.T) {
	for _, mode := range []string{"stale-cache", "default-plant", "cache-hit", "runpath-first"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := newLoaderFixture(t)
			late := filepath.Join(f.late, "dep.so")
			cached := filepath.Join(f.defaults, "dep.so")
			loaderELF(t, late, "int dep(void){return 1;}")
			loaderELF(t, cached, "int dep(void){return 2;}")
			cache := f.cache
			if mode != "default-plant" {
				cache = loaderCacheEntry("dep.so", cached)
			}
			if mode == "stale-cache" {
				if e := os.Remove(cached); e != nil {
					t.Fatal(e)
				}
			}
			q := linuxbackend.QualificationLoaderNew(f.reader, []string{f.early, f.defaults}, cache, nil)
			defer q.Close()
			rp := []string{}
			if mode == "runpath-first" {
				rp = []string{f.late}
			}
			record, e := q.Observe(ctx, "dep.so", rp)
			if mode == "stale-cache" {
				if !errors.Is(e, qualification.ErrRequired) {
					t.Fatal("stale cache admitted", record, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "cache-hit":
				if record.Path != cached || len(record.Locations) != 1 || record.Locations[0].Kind != "cache" {
					t.Fatal("cache selection changed", record)
				}
			case "runpath-first":
				if record.Path != late || len(record.Locations) != 2 || record.Locations[1].Kind != "runpath" {
					t.Fatal("cache preceded RUNPATH", record)
				}
			case "default-plant":
				if record.Path != cached || len(record.Locations) != 5 || record.Locations[0].State != "miss" || record.Locations[4].Kind != "default" {
					t.Fatal("default search evidence changed", record)
				}
			}
			pinned := linuxbackend.QualificationLoaderNew(f.reader, []string{f.early, f.defaults}, cache, []linuxbackend.ELFResolution{record})
			defer pinned.Close()
			if e = pinned.Revalidate(ctx); e != nil {
				t.Fatal("positive", e)
			}
			if mode == "default-plant" {
				loaderELF(t, filepath.Join(f.early, "dep.so"), "int dep(void){return 3;}")
				if e = pinned.Revalidate(ctx); !errors.Is(e, qualification.ErrRequired) {
					t.Fatal("earlier default plant admitted", e)
				}
			}
		})
	}
}
func loaderCacheEntry(name, path string) []byte {
	const start = 72
	text := []byte(name + "\x00" + path + "\x00")
	raw := make([]byte, start)
	copy(raw, "glibc-ld.so.cache1.1")
	raw[28] = 2
	binary.LittleEndian.PutUint32(raw[20:24], 1)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(len(text)))
	flags := uint32(0x303)
	if runtime.GOARCH == "arm64" {
		flags = 0xa03
	}
	binary.LittleEndian.PutUint32(raw[48:52], flags)
	binary.LittleEndian.PutUint32(raw[52:56], start)
	binary.LittleEndian.PutUint32(raw[56:60], start+uint32(len(name))+1)
	return append(raw, text...)
}
