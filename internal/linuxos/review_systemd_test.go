//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The diagnostic ABI view coalesces identical cross-module projections only;
// duplicates within either module must return no data. Public systemd admission
// is separately unavailable because aggregate NSS does not prove completion.
func TestReviewSystemdDuplicateEnumeration(t *testing.T) {
	for _, duplicate := range []string{"control", "passwd", "group", "shadow"} {
		t.Run(duplicate, func(t *testing.T) {
			f := newSystemdFixture(t)
			artifacts := filepath.Join(f.root, "artifacts")
			program := filepath.Join(artifacts, "probe")
			cmd := exec.Command("go", "build", "-p", "1", "-o", program, "../../cmd/swarma-nss-probe")
			if b, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("build collector: %v %s", e, b)
			}
			if e := os.Chmod(program, 0755); e != nil {
				t.Fatal(e)
			}
			// The optional-module form cannot silently fall back on empty paths.
			for _, args := range [][]string{{"--files-systemd", "100", "/unused", ""}, {"--files-systemd", "100", "", "/unused"}} {
				command := exec.Command(program, args...)
				output, e := command.Output()
				var exit *exec.ExitError
				if !errors.As(e, &exit) || exit.ExitCode() != 1 || len(output) != 0 {
					t.Fatal("malformed collector argv accepted", output, e)
				}
			}
			b, e := os.ReadFile("../nssprobe/testdata/module.c")
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(artifacts, "files.c"), b, 0600); e != nil {
				t.Fatal(e)
			}
			systemdSource := strings.ReplaceAll(string(b), "_nss_files_", "_nss_systemd_")
			counter := map[string]string{"passwd": "pw", "group": "gr", "shadow": "sp"}[duplicate]
			if counter != "" {
				systemdSource = strings.Replace(systemdSource, "if("+counter+"++)", "if("+counter+"++ > 1)", 1)
			}
			if e = os.WriteFile(filepath.Join(artifacts, "systemd.c"), []byte(systemdSource), 0600); e != nil {
				t.Fatal(e)
			}
			compileDirectoryFixture(t, filepath.Join(artifacts, "files.so"), filepath.Join(artifacts, "files.c"))
			compileDirectoryFixture(t, filepath.Join(artifacts, "systemd.so"), filepath.Join(artifacts, "systemd.c"))
			a := func(name string) ProtectedArtifact {
				return ProtectedArtifact{f.artifacts, name, filepath.Join(artifacts, name)}
			}
			// Explicit fixture resolver for this host toolchain; no production loader default.
			lib, e := OpenRoot("/usr/lib/x86_64-linux-gnu")
			if e != nil {
				t.Fatal(e)
			}
			defer lib.Close()
			resolve := closureResolverFixture{"libc.so.6": {lib, "libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"}, "ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}, "/lib64/ld-linux-x86-64.so.2": {lib, "ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"}}
			f.runtime.Files.Collector = a("probe")
			f.runtime.Files.Library = a("files.so")
			f.runtime.Files.Resolver = resolve
			f.runtime.Library = a("systemd.so")
			modules, e := f.capture()
			if e != nil {
				t.Fatal(e)
			}
			data, e := enumerateNSS(context.Background(), f.runtime.Files.Collector, []ProtectedArtifact{f.runtime.Files.Library, f.runtime.Library}, testLimits())
			if duplicate != "control" {
				if errorCode(e) != "directory_unknown" || data != nil {
					t.Fatalf("duplicate %s within systemd provider hidden: rows=%d error=%v", duplicate, strings.Count(string(data[duplicate]), "\n"), e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			etcpath := filepath.Join(f.root, "etc")
			conf, _, e := ParseNSSConfiguration([]byte("passwd: files systemd\ngroup: files systemd\nshadow: files systemd\n"), 100)
			if e != nil {
				t.Fatal(e)
			}
			for db, b := range data {
				if e = os.WriteFile(filepath.Join(etcpath, db), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(filepath.Join(etcpath, "nsswitch.conf"), []byte(conf.Passwd+conf.Group+conf.Shadow), 0600); e != nil {
				t.Fatal(e)
			}
			fence := &directoryFenceFixture{}
			d, e := NewQualifiedDirectory(f.runtime.Etc, DirectoryInputs{Configuration: conf, Modules: modules, UIDRange: IDInterval{24000, 24009}, GIDRange: IDInterval{24000, 24009}, ReservedNames: []string{"worker-fixture"}}, f.runtime, fence, testLimits())
			if e != nil {
				t.Fatal(e)
			}
			got, e := queryDirectory(d)
			requireDirectoryUnknown(t, got, e)
			if e = os.Mkdir(filepath.Join(etcpath, "userdb"), 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(etcpath, "userdb", "x.membership"), nil, 0600); e != nil {
				t.Fatal(e)
			}
			got, e = queryDirectory(d)
			requireDirectoryUnknown(t, got, e)

		})
	}
}
