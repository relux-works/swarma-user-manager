//go:build linux

package linuxos

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const nssLines = "# fixture\n passwd: files [NOTFOUND=return] files # retain spacing \n\tgroup:\tfiles [SUCCESS=merge]\nshadow: files"

// Capture preserves physical bytes and first-appearance module order. Invalid,
// ambiguous or incomplete syntax cannot silently acquire libc defaults.
func TestDirectoryNSSLines(t *testing.T) {
	for _, bad := range []string{
		"passwd: files\ngroup: files\n", nssLines + "\npasswd: files\n",
		strings.Replace(nssLines, "files [NOTFOUND=return]", "files \\\n files", 1),
		strings.Replace(nssLines, "NOTFOUND=return", "BOGUS=return", 1),
		strings.Replace(nssLines, "SUCCESS=merge", "SUCCESS=accept", 1),
		"passwd: [SUCCESS=return] files\ngroup: files\nshadow: files\n",
		"passwd: files [SUCCESS=return\ngroup: files\nshadow: files\n",
		nssLines + "\x00", nssLines + "\r", nssLines + string([]byte{0xff}),
	} {
		if _, _, e := ParseNSSConfiguration([]byte(bad), 100); errorCode(e) != "directory_unknown" {
			t.Fatalf("invalid syntax accepted or wrong refusal: %v", e)
		}
	}
	got, modules, e := ParseNSSConfiguration([]byte(nssLines), 100)
	want := NSSConfiguration{Passwd: " passwd: files [NOTFOUND=return] files # retain spacing \n", Group: "\tgroup:\tfiles [SUCCESS=merge]\n", Shadow: "shadow: files"}
	if e != nil || got != want || !reflect.DeepEqual(modules, []string{"files"}) {
		t.Fatalf("physical capture: %#v %v %v", got, modules, e)
	}
	_, mods, e := ParseNSSConfiguration([]byte("passwd: files [SUCCESS=return] systemd\ngroup: sss files\nshadow: compat\n"), 100)
	if e != nil || !reflect.DeepEqual(mods, []string{"files", "systemd", "sss", "compat"}) {
		t.Fatalf("reachable module order: %v %v", mods, e)
	}
	if _, _, e = ParseNSSConfiguration([]byte(nssLines), 0); errorCode(e) != "directory_unknown" {
		t.Fatal("unbounded capture", e)
	}
}

// Capture is read-only and requires the actual protected nsswitch object;
// symlinks, unsafe modes and missing files are not configuration absence.
func TestDirectoryNSSProtectedCapture(t *testing.T) {
	path := t.TempDir()
	d := fixtureDir(t, path)
	for _, mode := range []string{"missing", "symlink", "writable", "valid"} {
		t.Run(mode, func(t *testing.T) {
			p := filepath.Join(path, "nsswitch.conf")
			_ = os.Remove(p)
			if mode == "symlink" {
				if e := os.Symlink("other", p); e != nil {
					t.Fatal(e)
				}
			} else if mode != "missing" {
				if e := os.WriteFile(p, []byte(nssLines), 0600); e != nil {
					t.Fatal(e)
				}
				if mode == "writable" {
					if e := os.Chmod(p, 0666); e != nil {
						t.Fatal(e)
					}
				}
			}
			got, _, e := CaptureNSSConfiguration(context.Background(), d, testLimits())
			if mode == "valid" {
				if e != nil || got.Shadow != "shadow: files" {
					t.Fatal("valid protected capture", e)
				}
			} else if e == nil {
				t.Fatal("unsafe source captured")
			}
		})
	}
}

// The production no-follow/protection reader can capture the real host's public
// configuration without privilege or writes; recognizing systemd does not admit it.
func TestDirectoryHostCaptureReadOnly(t *testing.T) {
	d, e := OpenRoot("/etc")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	captured, names, e := CaptureNSSConfiguration(context.Background(), d, testLimits())
	if e != nil {
		t.Fatal("host public configuration", e)
	}
	if captured.Passwd == "" || captured.Group == "" || captured.Shadow == "" || len(names) == 0 {
		t.Fatal("incomplete real capture")
	}
	if _, e = (FilesNSSRuntime{}).CaptureModules(context.Background(), []string{"files", "systemd"}, testLimits()); errorCode(e) != "directory_unknown" {
		t.Fatal("systemd unqualified closure admitted", e)
	}
}
