//go:build linux

package linuxos

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A forged section view cannot erase a dependency still present in PT_DYNAMIC.
// The normal program/section pair captures both files before the bounded plant.
func TestDirectoryELFSectionProgramMismatch(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	for n, s := range map[string]string{"dep.c": "int dep(void){return 42;}", "root.c": "extern int dep(void); int use(void){return dep();}"} {
		if e := os.WriteFile(filepath.Join(path, n), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	dep, root := filepath.Join(path, "dep.so"), filepath.Join(path, "root.so")
	compileDirectoryFixture(t, dep, filepath.Join(path, "dep.c"))
	compileDirectoryFixture(t, root, filepath.Join(path, "root.c"), "-L"+path, "-Wl,--no-as-needed", "-l:dep.so")
	roots := []ProtectedArtifact{{d, "root.so", root}}
	resolver := closureResolverFixture{"dep.so": {d, "dep.so", dep}}
	if files, _, e := CaptureImplementationClosure(context.Background(), roots, resolver, testLimits()); e != nil || len(files) != 2 {
		t.Fatal("normal loader closure", e)
	}
	b, e := os.ReadFile(root)
	if e != nil {
		t.Fatal(e)
	}
	if b[4] != 2 || b[5] != 1 {
		t.Fatal("fixture requires ELF64 little endian")
	}
	off := binary.LittleEndian.Uint64(b[40:48])
	count := binary.LittleEndian.Uint16(b[60:62])
	stride := binary.LittleEndian.Uint16(b[58:60])
	planted := false
	for j := uint16(0); j < count; j++ {
		base := off + uint64(j)*uint64(stride)
		if elf.SectionType(binary.LittleEndian.Uint32(b[base+4:base+8])) != elf.SHT_DYNAMIC {
			continue
		}
		size := binary.LittleEndian.Uint64(b[base+32 : base+40])
		fake := uint64(len(b))
		b = append(b, make([]byte, size)...)
		binary.LittleEndian.PutUint64(b[base+24:base+32], fake)
		planted = true
		break
	}
	if !planted {
		t.Fatal("section mismatch plant not applied")
	}
	if e = os.WriteFile(root, b, 0755); e != nil {
		t.Fatal(e)
	}
	if _, _, e = CaptureImplementationClosure(context.Background(), roots, resolver, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("section/program disagreement admitted", e)
	}
}

// ASCII space, tab, vertical tab and form feed are admitted consistently;
// non-ASCII separators and service-name suffixes are never normalized to files.
func TestDirectoryNSSASCIIGrammar(t *testing.T) {
	for _, space := range []string{" ", "\t", "\v", "\f"} {
		d, path, _, _ := directoryProviderFixture(t)
		raw := "passwd:" + space + "files\ngroup:" + space + "files\nshadow:" + space + "files\n"
		cfg, _, e := ParseNSSConfiguration([]byte(raw), 100)
		if e != nil {
			t.Fatal("ASCII capture", e)
		}
		d.inputs.Configuration = cfg
		if e = os.WriteFile(filepath.Join(path, "nsswitch.conf"), []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = queryDirectory(d); e != nil {
			t.Fatal("ASCII admission", e)
		}
	}
	for _, s := range []string{"\u00a0files", "files\u00a0", "\u2003files", "files\u202f"} {
		raw := "passwd: " + s + "\ngroup: files\nshadow: files\n"
		if _, _, e := ParseNSSConfiguration([]byte(raw), 100); errorCode(e) != "directory_unknown" {
			t.Fatal("Unicode normalization", e)
		}
	}
}

// A second coherent agreed tuple is a valid neighbor. Name, numeric identity,
// lock and membership differences in that second tuple remain disagreements.
func TestDirectorySecondIdentityDisagreement(t *testing.T) {
	for _, mode := range []string{"uid", "gid", "lock", "membership", "duplicate", "valid"} {
		t.Run(mode, func(t *testing.T) {
			d, path, r, _ := directoryProviderFixture(t)
			additions := map[string]string{"passwd": "worker-second:x:24001:24001::/opt/swarma/workers/worker-second:/usr/sbin/nologin\n", "group": "worker-second:x:24001:\n", "shadow": "worker-second:!:::::::\n"}
			for db, text := range additions {
				r.data[db] = append(r.data[db], []byte(text)...)
				if e := os.WriteFile(filepath.Join(path, db), r.data[db], 0600); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "uid":
				r.data["passwd"] = []byte(strings.Replace(string(r.data["passwd"]), "second:x:24001:", "second:x:24002:", 1))
			case "gid":
				r.data["group"] = []byte(strings.Replace(string(r.data["group"]), "second:x:24001:", "second:x:24002:", 1))
			case "lock":
				r.data["shadow"] = []byte(strings.Replace(string(r.data["shadow"]), "second:!:", "second::", 1))
			case "membership":
				r.data["group"] = []byte(strings.Replace(string(r.data["group"]), "second:x:24001:", "second:x:24001:worker-fixture", 1))
			case "duplicate":
				r.data["passwd"] = append(r.data["passwd"], []byte(additions["passwd"])...)
			}
			got, e := queryDirectory(d)
			if mode == "valid" {
				if e != nil || len(got.Accounts) != 1 {
					t.Fatal("agreed second identity refused", e)
				}
			} else if errorCode(e) != "directory_unknown" {
				t.Fatal("second identity disagreement admitted", e)
			}
		})
	}
}
