//go:build linux

package linuxos

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PT_DYNAMIC's file range must agree with its actual PT_LOAD mapping. A forged
// file offset cannot conceal the dependency used by a real dlopen execution.
func TestReviewRound2DynamicLoadMapping(t *testing.T) {
	for _, mode := range []string{"control", "offset-decoy", "vaddr-outside-load"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			d := fixtureDir(t, path)
			for name, src := range map[string]string{"dep.c": "int dependency(void){return 42;}", "root.c": "extern int dependency(void); int root_value(void){return dependency();}"} {
				if e := os.WriteFile(filepath.Join(path, name), []byte(src), 0600); e != nil {
					t.Fatal(e)
				}
			}
			dep := filepath.Join(path, "dep.so")
			root := filepath.Join(path, "root.so")
			compileDirectoryFixture(t, dep, "-Wl,-soname,dep.so", filepath.Join(path, "dep.c"))
			compileDirectoryFixture(t, root, filepath.Join(path, "root.c"), "-L"+path, "-Wl,--no-as-needed", "-l:dep.so")
			roots := []ProtectedArtifact{{d, "root.so", root}}
			resolver := closureResolverFixture{"dep.so": {d, "dep.so", dep}}
			original, _, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
			if e != nil || len(original) != 2 {
				t.Fatal("normal dependency control", original, e)
			}
			if mode == "control" {
				return
			}
			b, e := os.ReadFile(root)
			if e != nil {
				t.Fatal(e)
			}
			if b[4] != 2 || b[5] != 1 {
				t.Fatal("ELF64 little-endian fixture required")
			}
			u16 := binary.LittleEndian.Uint16
			u32 := binary.LittleEndian.Uint32
			u64 := binary.LittleEndian.Uint64
			put := binary.LittleEndian.PutUint64
			phoff := u64(b[32:40])
			phsize := uint64(u16(b[54:56]))
			phnum := u16(b[56:58])
			planted := false
			for i := uint16(0); i < phnum; i++ {
				h := phoff + uint64(i)*phsize
				if elf.ProgType(u32(b[h:h+4])) != elf.PT_DYNAMIC {
					continue
				}
				if mode == "vaddr-outside-load" {
					put(b[h+16:h+24], 0x7f0000000000)
					planted = true
					break
				}
				start, size := u64(b[h+8:h+16]), u64(b[h+32:h+40])
				fake := uint64(len(b))
				copydyn := append([]byte(nil), b[start:start+size]...)
				removed := false
				for off := uint64(0); off < size; off += 16 {
					if elf.DynTag(u64(copydyn[off:off+8])) == elf.DT_NEEDED {
						put(copydyn[off:off+8], uint64(elf.DT_DEBUG))
						put(copydyn[off+8:off+16], 0)
						removed = true
					}
				}
				if !removed {
					t.Fatal("no dependency to hide")
				}
				b = append(b, copydyn...)
				put(b[h+8:h+16], fake)
				shoff, shsize, shnum := u64(b[40:48]), uint64(u16(b[58:60])), u16(b[60:62])
				section := false
				for j := uint16(0); j < shnum; j++ {
					q := shoff + uint64(j)*shsize
					if elf.SectionType(u32(b[q+4:q+8])) == elf.SHT_DYNAMIC {
						put(b[q+24:q+32], fake)
						section = true
					}
				}
				if !section {
					t.Fatal("no section to keep consistent with decoy")
				}
				planted = true
				break
			}
			if !planted {
				t.Fatal("plant missing")
			}
			if e = os.WriteFile(root, b, 0755); e != nil {
				t.Fatal(e)
			}
			if mode == "offset-decoy" {
				loader := exec.Command("/usr/bin/python3", "-c", "import ctypes,sys; ctypes.CDLL(sys.argv[1]); r=ctypes.CDLL(sys.argv[2]); assert r.root_value()==42", dep, root)
				if out, e := loader.CombinedOutput(); e != nil {
					t.Fatalf("real loader control failed: %v %s", e, out)
				}
				t.Log("real loader still resolves dep.so and returns 42")
			}
			files, _, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits())
			if errorCode(e) != "directory_unknown" {
				t.Fatalf("unmapped or inconsistent PT_DYNAMIC admitted: mode=%s captured=%v err=%v", mode, files, e)
			}
		})
	}
}

// The supported separator set must agree with actual libc service parsing;
// explicitly unsupported CR, continuations and other controls must refuse.
func TestReviewRound2NSSGrammar(t *testing.T) {
	for _, space := range []string{" ", "\t", "\v", "\f", "\u00a0", "\u2003", "\x01", "\x08", "\x1c", "\x7f", "\r", "\\\n"} {
		for _, suffix := range []bool{false, true} {
			body := space + "files"
			if suffix {
				body = "files" + space
			}
			t.Run(body, func(t *testing.T) {
				supported := strings.Contains(" \t\v\f", space)
				d, path, r, f := directoryProviderFixture(t)
				raw := "passwd: " + body + "\ngroup: files\nshadow: files\n"
				conf, _, e := ParseNSSConfiguration([]byte(raw), 100)
				if !supported {
					if errorCode(e) != "directory_unknown" {
						t.Fatalf("unsupported bytes captured: %q %v", space, e)
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte(raw), 0600); e != nil {
					t.Fatal(e)
				}
				in := d.inputs
				in.Configuration = conf
				d, e = NewQualifiedDirectory(d.etc, in, r, f, testLimits())
				if e != nil {
					t.Fatal(e)
				}
				got, e := queryDirectory(d)
				if e != nil || len(got.Accounts) != 1 {
					t.Fatalf("supported grammar refused: %q %v", space, e)
				}
			})
		}
	}
	// Action clauses remain inadmissible, including clauses whose internal
	// separator is Unicode. Capture behavior is recorded separately as a limit.
	for _, space := range []string{" ", "\t", "\v", "\f", "\u00a0", "\u2003"} {
		d, path, r, f := directoryProviderFixture(t)
		raw := "passwd: files [" + space + "SUCCESS=return]\ngroup: files\nshadow: files\n"
		conf, _, e := ParseNSSConfiguration([]byte(raw), 100)
		if e != nil {
			continue
		}
		if e = os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		in := d.inputs
		in.Configuration = conf
		d, e = NewQualifiedDirectory(d.etc, in, r, f, testLimits())
		if e != nil {
			continue
		}
		got, e := queryDirectory(d)
		requireDirectoryUnknown(t, got, e)
		t.Logf("action separator %q captured, but refused at admission", space)
	}
}

// An in-range group's name belongs to the comparison namespace even when its
// same-named passwd row has numbers outside the station ranges. Local/NSS sides
// must be symmetric; complete matching views remain the neighboring controls.
func TestReviewRound2GroupNameAccountCoverage(t *testing.T) {
	for _, mode := range []string{"neither-control", "both-control", "local-only", "remote-only", "different-home"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			r.data["group"] = append(r.data["group"], []byte("worker-group:x:24001:\n")...)
			r.data["shadow"] = append(r.data["shadow"], []byte("worker-group:!:::::::\n")...)
			local := NSSDatabases{}
			for db, b := range r.data {
				local[db] = append([]byte{}, b...)
			}
			row := "worker-group:x:25000:25000::/home/group:/usr/sbin/nologin\n"
			if mode == "both-control" || mode == "local-only" || mode == "different-home" {
				local["passwd"] = append(local["passwd"], []byte(row)...)
			}
			if mode == "both-control" || mode == "remote-only" {
				r.data["passwd"] = append(r.data["passwd"], []byte(row)...)
			}
			if mode == "different-home" {
				r.data["passwd"] = append(r.data["passwd"], []byte(strings.Replace(row, "/home/group", "/home/other", 1))...)
			}
			for db, b := range local {
				if e := os.WriteFile(filepath.Join(path, db), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			got, e := queryDirectory(d)
			if strings.HasSuffix(mode, "control") {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal("matching group-name account view refused", e)
				}
				return
			}
			if errorCode(e) != "directory_unknown" {
				t.Fatalf("in-range group name's passwd disagreement admitted: mode=%s accounts=%d err=%v", mode, len(got.Accounts), e)
			}
		})
	}
}

// Both old/new loader search tags and literal $ORIGIN are explicitly unsupported,
// including when optional ELF section headers have been removed.
func TestReviewRound2ForbiddenLoaderSearch(t *testing.T) {
	for _, kind := range []string{"rpath", "runpath"} {
		for _, sectionless := range []bool{false, true} {
			name := kind
			if sectionless {
				name += "-sectionless"
			}
			t.Run(name, func(t *testing.T) {
				path := t.TempDir()
				d := fixtureDir(t, path)
				source := filepath.Join(path, "root.c")
				root := filepath.Join(path, "root.so")
				if e := os.WriteFile(source, []byte("int value(void){return 42;}"), 0600); e != nil {
					t.Fatal(e)
				}
				tag := "-Wl,--enable-new-dtags,-rpath,$ORIGIN"
				if kind == "rpath" {
					tag = "-Wl,--disable-new-dtags,-rpath,$ORIGIN"
				}
				compileDirectoryFixture(t, root, source, tag)
				if sectionless {
					b, e := os.ReadFile(root)
					if e != nil {
						t.Fatal(e)
					}
					if b[4] != 2 || b[5] != 1 {
						t.Fatal("ELF64 little-endian required")
					}
					binary.LittleEndian.PutUint64(b[40:48], 0)
					binary.LittleEndian.PutUint16(b[60:62], 0)
					binary.LittleEndian.PutUint16(b[62:64], 0)
					if e = os.WriteFile(root, b, 0755); e != nil {
						t.Fatal(e)
					}
				}
				_, _, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{{d, "root.so", root}}, closureResolverFixture{}, testLimits())
				if errorCode(e) != "directory_unknown" || !strings.Contains(e.Error(), "closure_loader_syntax") {
					t.Fatalf("unsupported search tag did not receive intended refusal: %v", e)
				}
			})
		}
	}
}
