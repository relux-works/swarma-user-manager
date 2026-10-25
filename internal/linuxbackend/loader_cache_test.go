//go:build linux

package linuxbackend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

type cacheTestRow struct{ name, path string }

func cacheTable(rows []cacheTestRow) []byte {
	start := 48 + 24*len(rows)
	b := make([]byte, start)
	copy(b, "glibc-ld.so.cache1.1")
	b[28] = 2
	binary.LittleEndian.PutUint32(b[20:], uint32(len(rows)))
	var text []byte
	for i, r := range rows {
		row := b[48+24*i : 48+24*(i+1)]
		binary.LittleEndian.PutUint32(row, cacheABIFlags())
		binary.LittleEndian.PutUint32(row[4:], uint32(start+len(text)))
		text = append(text, []byte(r.name+"\x00")...)
		binary.LittleEndian.PutUint32(row[8:], uint32(start+len(text)))
		text = append(text, []byte(r.path+"\x00")...)
	}
	binary.LittleEndian.PutUint32(b[24:], uint32(len(text)))
	return append(b, text...)
}

// glibc's descending _dl_cache_libcmp order puts 10 before 2, treats digit runs
// numerically, and sorts a digit after even a higher-byte non-digit. Unique
// numeric spellings and identical duplicate rows select their sole path; a miss
// remains a miss. This is the supported zero-hwcaps/native-ABI profile only.
func TestLoaderCacheNumericSelection(t *testing.T) {
	rows := []cacheTestRow{{"libx.so.10", "/usr/lib/ten"}, {"libx.so.2", "/usr/lib/two"}, {"libx.so.1", "/usr/lib/one"}, {"libx.so.z", "/usr/lib/non-digit"}}
	for _, tc := range []struct{ name, want string }{{"libx.so.10", "/usr/lib/ten"}, {"libx.so.2", "/usr/lib/two"}, {"libx.so.1", "/usr/lib/one"}, {"libx.so.01", "/usr/lib/one"}, {"libx.so.z", "/usr/lib/non-digit"}} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := cacheResolve(cacheTable(rows), tc.name)
			if e != nil || got != tc.want {
				t.Fatalf("numeric cache selection: got %q %v, want %q", got, e, tc.want)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		got, e := cacheResolve(cacheTable(rows), "libx.so.3")
		if got != "" || !errors.Is(e, errCacheMiss) {
			t.Fatal("numeric miss changed", got, e)
		}
	})
	t.Run("single-key", func(t *testing.T) {
		single := cacheTable([]cacheTestRow{{"libx.so.1", "/usr/lib/one"}})
		if got, e := cacheResolve(single, "libx.so.1"); e != nil || got != "/usr/lib/one" {
			t.Fatal("single-key control", got, e)
		}
	})
	t.Run("identical-rows", func(t *testing.T) {
		same := cacheTable([]cacheTestRow{{"libx.so.1", "/usr/lib/one"}, {"libx.so.1", "/usr/lib/one"}})
		if got, e := cacheResolve(same, "libx.so.1"); e != nil || got != "/usr/lib/one" {
			t.Fatal("identical rows refused", got, e)
		}
	})
	t.Run("integer-boundaries", func(t *testing.T) {
		limits := cacheTable([]cacheTestRow{{"libv.so.2147483647.0", "/usr/lib/max"}, {"libv.so.2a", "/usr/lib/suffix"}, {"libv.so.2", "/usr/lib/prefix"}, {"libv.so.0", "/usr/lib/zero"}})
		for _, tc := range []struct{ name, want string }{{"libv.so.02147483647.00", "/usr/lib/max"}, {"libv.so.2a", "/usr/lib/suffix"}, {"libv.so.2", "/usr/lib/prefix"}, {"libv.so.000", "/usr/lib/zero"}} {
			if got, e := cacheResolve(limits, tc.name); e != nil || got != tc.want {
				t.Fatal("numeric boundary", tc.name, got, e)
			}
		}
	})
}

// Full-table validation refuses misordering and distinct spellings of the same
// numeric key even when the requested exact key is elsewhere. Numeric overflow,
// non-ASCII/embedded-NUL queries and ambiguous matches refuse without a path;
// these are explicit unsupported shapes, never a cache miss/default fallback.
func TestLoaderCacheTableRefusal(t *testing.T) {
	for _, mode := range []string{"misordered", "byte-sorted", "numeric-alias", "numeric-alias-reversed", "unqueried-alias", "overflow-key", "overflow-query", "non-ascii-key", "non-ascii-query", "nul-query", "ambiguous"} {
		t.Run(mode, func(t *testing.T) {
			name := "libx.so.1"
			rows := []cacheTestRow{{"libx.so.2", "/usr/lib/two"}, {name, "/usr/lib/one"}}
			switch mode {
			case "misordered":
				rows[0], rows[1] = rows[1], rows[0]
			case "byte-sorted":
				rows = []cacheTestRow{{"libx.so.2", "/usr/lib/two"}, {"libx.so.10", "/usr/lib/ten"}, {name, "/usr/lib/one"}}
			case "numeric-alias":
				rows = []cacheTestRow{{"libx.so.01", "/usr/lib/one"}, {name, "/usr/lib/one"}}
			case "numeric-alias-reversed":
				rows = []cacheTestRow{{name, "/usr/lib/one"}, {"libx.so.01", "/usr/lib/one"}}
			case "unqueried-alias":
				rows = append([]cacheTestRow{{"libz.so.01", "/usr/lib/z"}, {"libz.so.1", "/usr/lib/z"}}, rows...)
			case "overflow-key":
				rows = append([]cacheTestRow{{"libz.so.2147483648", "/usr/lib/z"}}, rows...)
			case "overflow-query":
				name = "libx.so.2147483648"
			case "non-ascii-key":
				rows = append([]cacheTestRow{{"lib\xff.so.1", "/usr/lib/z"}}, rows...)
			case "non-ascii-query":
				name = "lib\xff.so.1"
			case "nul-query":
				name += "\x00decoy"
			case "ambiguous":
				rows = append(rows, cacheTestRow{name, "/other/one"})
			}
			got, e := cacheResolve(cacheTable(rows), name)
			if got != "" || !errors.Is(e, qualification.ErrRequired) {
				t.Fatal("unsupported cache/query did not refuse", got, e)
			}
		})
	}
}

// The read-only host cache must refuse each SONAME with a foreign-ABI row;
// otherwise the model must agree with native dlopen+dlinfo on device/inode.
// At least one SONAME must prove agreement, so all-refusal cannot pass. This
// exercises this host's glibc, not a claim that the host runs glibc 2.42.
func TestLoaderCacheHostAgreement(t *testing.T) {
	b, e := os.ReadFile("/etc/ld.so.cache")
	if e != nil {
		t.Fatal(e)
	}
	before := bytes.Clone(b)
	dir := t.TempDir()
	source := filepath.Join(dir, "lookup.c")
	program := filepath.Join(dir, "lookup")
	code := `#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h)return 3;
 struct link_map *m=0;
 if(dlinfo(h,RTLD_DI_LINKMAP,&m)!=0||!m||!m->l_name||!*m->l_name)return 4;
 puts(m->l_name);return dlclose(h)!=0;
}`
	if e = os.WriteFile(source, []byte(code), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("/usr/bin/cc", "-o", program, source, "-ldl")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("native cache helper: %v %s", e, out)
	}
	// glibc's own cache printer is independent of cacheResolve's binary reader
	// and ABI flags. Its annotations, not the model's verdict, select expectations.
	// ABI spellings: glibc 2.42 elf/cache.c print_entry (x86-64 and AArch64).
	nativeABI := ""
	switch runtime.GOARCH {
	case "amd64":
		nativeABI = "libc6,x86-64"
	case "arm64":
		nativeABI = "libc6,AArch64"
	default:
		t.Fatal("host agreement requires a reviewed native ABI")
	}
	cmd = exec.Command("/usr/sbin/ldconfig", "-p", "-C", "/etc/ld.so.cache")
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Dir = "/"
	out, e := cmd.Output()
	if e != nil {
		t.Fatal("independent glibc cache inventory", e)
	}
	foreignABIs := map[string][]string{"libc.so.6": nil, "libm.so.6": nil, "libnss_systemd.so.2": nil}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if _, queried := foreignABIs[name]; !queried {
			continue
		}
		_, annotation, ok := strings.Cut(strings.TrimSpace(line), " (")
		if !ok {
			t.Fatalf("unrecognized glibc cache row: %q", line)
		}
		annotation, _, ok = strings.Cut(annotation, ") => ")
		if !ok {
			t.Fatalf("unrecognized glibc cache annotation: %q", line)
		}
		// A following ', hwcap: ...' describes selection, not the entry ABI.
		abi, _, _ := strings.Cut(annotation, ", ")
		if abi != nativeABI {
			foreignABIs[name] = append(foreignABIs[name], abi)
		}
	}
	agreements := 0
	for _, name := range []string{"libc.so.6", "libm.so.6", "libnss_systemd.so.2"} {
		t.Run(name, func(t *testing.T) {
			got, e := cacheResolve(b, name)
			if abis := foreignABIs[name]; len(abis) != 0 {
				if got != "" || e != qualification.ErrRequired {
					t.Fatalf("foreign-ABI cache row must refuse with qualification_required: got %q, err %v", got, e)
				}
				t.Logf("%s: foreign cache ABIs %v (native %s); loader profile refuses by design", name, abis, nativeABI)
				return
			}
			if e != nil {
				t.Fatal("host positive cache refused", e)
			}
			cmd := exec.Command(program, name)
			cmd.Env = []string{}
			out, e := cmd.Output()
			if e != nil {
				t.Fatal("native lookup", e)
			}
			native := strings.TrimSuffix(string(out), "\n")
			wantInfo, e := os.Stat(native)
			if e != nil {
				t.Fatal(e)
			}
			gotInfo, e := os.Stat(got)
			if e != nil {
				t.Fatal(e)
			}
			if !os.SameFile(wantInfo, gotInfo) {
				t.Fatalf("native object %q differs from cache model %q", native, got)
			}
			t.Logf("%s: model=%s native=%s", name, got, native)
			agreements++
		})
	}
	if agreements == 0 {
		t.Error("no SONAME exercised native loader agreement")
	}
	after, e := os.ReadFile("/etc/ld.so.cache")
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("host cache changed during read-only control", e)
	}
}
