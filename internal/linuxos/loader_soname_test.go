//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Duplicate SONAMEs on distinct objects refuse in either order, regardless of
// whether a later NEEDED happens to use the alias. Distinct names and repeat
// roots for the very same object remain valid controls.
func TestLoaderDuplicateSONAME(t *testing.T) {
	for _, mode := range []string{"duplicate", "reversed", "root-name-alias", "root-name-alias-reversed", "distinct", "same-object"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			d := fixtureDir(t, root)
			source := filepath.Join(root, "root.c")
			if e := os.WriteFile(source, []byte("int value(void){return 1;}"), 0600); e != nil {
				t.Fatal(e)
			}
			first := ProtectedArtifact{d, "first.so", filepath.Join(root, "first.so")}
			second := ProtectedArtifact{d, "second.so", filepath.Join(root, "second.so")}
			compileDirectoryFixture(t, first.Path, source, "-Wl,-soname,shared.so")
			name := "shared.so"
			if mode == "root-name-alias" || mode == "root-name-alias-reversed" {
				name = first.Path
			}
			if mode == "distinct" {
				name = "other.so"
			}
			compileDirectoryFixture(t, second.Path, source, "-Wl,-soname,"+name)
			roots := []ProtectedArtifact{first, second}
			if mode == "reversed" || mode == "root-name-alias-reversed" {
				roots = []ProtectedArtifact{second, first}
			}
			if mode == "same-object" {
				roots = []ProtectedArtifact{first, first}
			}
			files, digest, e := CaptureImplementationClosure(context.Background(), roots, closureResolverFixture{}, testLimits())
			if mode != "distinct" && mode != "same-object" {
				if !loaderErrorStep(e, "closure_soname_alias") || files != nil || digest != "" {
					t.Fatal("duplicate SONAME admitted", files, digest, e)
				}
			} else {
				want := 2
				if mode == "same-object" {
					want = 1
				}
				if e != nil || len(files) != want || digest == "" {
					t.Fatal("nonalias control refused", files, e)
				}
			}
		})
	}
}

// SONAME aliases come from the runtime dynamic/string mapping, including when
// optional sections are absent. Malformed, ambiguous or token-bearing SONAMEs
// refuse specifically, without exporting even a partial implementation closure.
func TestLoaderSONAMEDynamicView(t *testing.T) {
	for _, mode := range []string{"valid", "sectionless", "empty", "out-of-range", "duplicate", "token"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			d := fixtureDir(t, root)
			source, path := filepath.Join(root, "root.c"), filepath.Join(root, "root.so")
			if e := os.WriteFile(source, []byte("int value(void){return 1;}"), 0600); e != nil {
				t.Fatal(e)
			}
			compileDirectoryFixture(t, path, source, "-Wl,-soname,shared.so")
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			object, e := elf.NewFile(bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			changed := mode == "valid"
			for _, p := range object.Progs {
				if p.Type != elf.PT_DYNAMIC {
					continue
				}
				for off := p.Off; off+16 <= p.Off+p.Filesz; off += 16 {
					tag := elf.DynTag(binary.LittleEndian.Uint64(raw[off : off+8]))
					if tag == elf.DT_SONAME && (mode == "empty" || mode == "out-of-range") {
						value := uint64(0)
						if mode == "out-of-range" {
							value = ^uint64(0)
						}
						binary.LittleEndian.PutUint64(raw[off+8:off+16], value)
						changed = true
					}
					if tag == elf.DT_GNU_HASH && mode == "duplicate" {
						binary.LittleEndian.PutUint64(raw[off:off+8], uint64(elf.DT_SONAME))
						changed = true
					}
				}
			}
			if mode == "sectionless" {
				binary.LittleEndian.PutUint64(raw[40:48], 0)
				binary.LittleEndian.PutUint16(raw[60:62], 0)
				binary.LittleEndian.PutUint16(raw[62:64], 0)
				changed = true
			}
			if mode == "token" {
				at := bytes.Index(raw, []byte("shared.so"))
				if at >= 0 {
					raw[at], changed = '$', true
				}
			}
			if !changed {
				t.Fatal("SONAME mutation was not applied")
			}
			if e = os.WriteFile(path, raw, 0755); e != nil {
				t.Fatal(e)
			}
			files, digest, e := CaptureImplementationClosure(context.Background(), []ProtectedArtifact{{d, "root.so", path}}, closureResolverFixture{}, testLimits())
			if mode == "valid" || mode == "sectionless" {
				if e != nil || len(files) != 1 || digest == "" {
					t.Fatal("runtime SONAME control refused", files, digest, e)
				}
			} else if !loaderErrorStep(e, "closure_loader_view") || files != nil || digest != "" {
				t.Fatal("invalid runtime SONAME was not specifically refused", files, digest, e)
			}
		})
	}
}
