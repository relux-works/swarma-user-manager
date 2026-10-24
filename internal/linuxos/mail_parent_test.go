//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func mailPolicyFixture() MailSpoolPolicy {
	return MailSpoolPolicy{Limits: testLimits(), StationRanges: []IDInterval{{24000, 24099}, {25000, 25099}}}
}
func mailDatabaseFixture() accountDatabases {
	return accountDatabases{data: NSSDatabases{
		"passwd": []byte("root:x:0:0::/:/bin/bash\nmail:x:8:8::/var/mail:/usr/sbin/nologin\n"),
		"group":  []byte("root:x:0:\nmail:x:8:\n"),
		"shadow": []byte("root:!:::::::\nmail:!:::::::\n"),
	}, gshadow: []byte("root:*::\nmail:!::\n")}
}
func requireMailRefusal(t *testing.T, e error, code, op string) {
	t.Helper()
	var f *Error
	if !errors.As(e, &f) || f.Code != code || f.Operation != op {
		t.Fatalf("want %s/%s, got %v", code, op, e)
	}
}

// Synthetic root metadata validates the exact mailbox-only mode/group rule;
// this does not claim that unprivileged fixtures performed root:mail chown.
func TestMailParentMetadataAdmission(t *testing.T) {
	for _, mode := range []string{"mail-2775-control", "mail-0755-control", "root-0755-control", "root-2775", "world-writable", "plain-group-write", "sticky", "special", "private-mode", "foreign-owner", "not-directory", "unresolved-group", "group-alias", "group-non-system", "station-gid", "station-gid-second-range", "unlocked-group", "empty-group", "missing-gshadow", "missing-mail", "unknown-ranges", "invalid-range", "invalid-limit"} {
		t.Run(mode, func(t *testing.T) {
			a, p := mailDatabaseFixture(), mailPolicyFixture()
			st := unix.Stat_t{Mode: unix.S_IFDIR | 02775, Uid: 0, Gid: 8, Nlink: 2}
			want, code := "mail_parent", "qualification_failed"
			switch mode {
			case "mail-2775-control":
				want = ""
			case "mail-0755-control":
				st.Mode = unix.S_IFDIR | 0755
				want = ""
			case "root-0755-control":
				st.Mode = unix.S_IFDIR | 0755
				st.Gid = 0
				want = ""
			case "root-2775":
				st.Gid = 0
			case "world-writable":
				st.Mode = unix.S_IFDIR | 02777
			case "plain-group-write":
				st.Mode = unix.S_IFDIR | 0775
			case "sticky":
				st.Mode = unix.S_IFDIR | 03775
			case "special":
				st.Mode = unix.S_IFDIR | 06775
			case "private-mode":
				st.Mode = unix.S_IFDIR | 0700
			case "foreign-owner":
				st.Uid = 1
			case "not-directory":
				st.Mode = unix.S_IFREG | 02775
			case "unresolved-group":
				st.Gid = 9
				want = "mail_group"
			case "group-alias":
				a.data["group"] = append(a.data["group"], []byte("alias:x:8:\n")...)
				code = "directory_unknown"
				want = "complete_database"
			case "group-non-system":
				st.Gid = 1000
				want = "mail_group"
			case "station-gid":
				p.StationRanges[0] = IDInterval{8, 8}
				want = "mail_group"
			case "station-gid-second-range":
				p.StationRanges[1] = IDInterval{8, 8}
				want = "mail_group"
			case "unlocked-group":
				a.gshadow = []byte("root:*::\nmail:fixture-hash::\n")
				want = "mail_group_credential"
			case "empty-group":
				a.gshadow = []byte("root:*::\nmail:::\n")
				want = "mail_group_credential"
			case "missing-gshadow":
				a.gshadow = []byte("root:*::\n")
				want = "mail_group_credential"
			case "missing-mail":
				a.data["group"] = []byte("root:x:0:\n")
				want = "mail_group_credential"
			case "unknown-ranges":
				p.StationRanges = nil
				code = "qualification_invalid"
				want = "mail_policy"
			case "invalid-range":
				p.StationRanges[0] = IDInterval{5, 4}
				code = "qualification_invalid"
				want = "mail_policy"
			case "invalid-limit":
				p.Limits.Entries = 0
				code = "qualification_invalid"
				want = "mail_policy"
			}
			out, e := qualifyMailParent(st, 0, 0, a, p)
			if want != "" {
				requireMailRefusal(t, e, code, want)
				return
			}
			if e != nil || out.Metadata != st {
				t.Fatal("positive control", out, e)
			}
			if st.Mode&0020 != 0 {
				if out.Group != "mail" || len(out.Writers) != 1 || out.Writers[0] != (mailWriter{"mail", 8, 8, "/usr/sbin/nologin", true, 1}) {
					t.Fatal("accepted writer evidence incomplete", out)
				}
			} else if len(out.Writers) != 0 {
				t.Fatal("0755 granted group write", out)
			}
		})
	}
}

// Every access path (primary GID, group member, gshadow member or admin) must
// resolve to a locked nologin system account outside ALL station intervals.
// Neighbor controls exercise every permitted shell and lock prefix/boundary.
func TestMailParentWriterAdmission(t *testing.T) {
	for _, source := range []string{"primary", "member", "gshadow-member", "admin"} {
		for _, mode := range []string{"control", "sbin-nologin", "bin-false", "usr-bin-false", "star-lock", "prefixed-lock", "boundary-999", "explicit-boundary", "login-shell", "unlocked", "empty-password", "missing-shadow", "station-uid", "station-uid-second-range", "non-system-uid", "missing-passwd", "empty-member"} {
			if source == "primary" && (mode == "missing-passwd" || mode == "empty-member") {
				continue
			}
			t.Run(source+"/"+mode, func(t *testing.T) {
				a, p := mailDatabaseFixture(), mailPolicyFixture()
				uid, gid := uint32(8), uint32(99)
				shell, password := "/usr/sbin/nologin", "!"
				members, gsMembers, admins := "", "", ""
				sources := uint8(0)
				switch source {
				case "primary":
					gid = 8
					sources = 1
				case "member":
					members = "mail"
					sources = 2
				case "gshadow-member":
					gsMembers = "mail"
					sources = 4
				case "admin":
					admins = "mail"
					sources = 8
				}
				want := ""
				switch mode {
				case "sbin-nologin":
					shell = "/sbin/nologin"
				case "bin-false":
					shell = "/bin/false"
				case "usr-bin-false":
					shell = "/usr/bin/false"
				case "star-lock":
					password = "*"
				case "prefixed-lock":
					password = "!fixture-disabled"
				case "boundary-999":
					uid = 999
				case "explicit-boundary":
					uid = 1500
					p.SystemBoundary = 2000
				case "login-shell":
					shell = "/bin/bash"
					want = "mail_writer_shell"
				case "unlocked":
					password = "fixture-hash"
					want = "mail_writer"
				case "empty-password":
					password = ""
					want = "mail_writer"
				case "missing-shadow":
					want = "mail_writer"
				case "station-uid":
					uid = 9
					p.StationRanges[0] = IDInterval{9, 9}
					want = "mail_writer"
				case "station-uid-second-range":
					uid = 9
					p.StationRanges[1] = IDInterval{9, 9}
					want = "mail_writer"
				case "non-system-uid":
					uid = 1000
					want = "mail_writer"
				case "missing-passwd":
					want = "mail_writer"
				case "empty-member":
					want = "mail_writer"
					switch source {
					case "member":
						members = "mail,"
					case "gshadow-member":
						gsMembers = "mail,"
					case "admin":
						admins = "mail,"
					}
				}
				a.data["passwd"] = []byte(fmt.Sprintf("root:x:0:0::/:/bin/bash\nmail:x:%d:%d::/var/mail:%s\n", uid, gid, shell))
				if mode == "missing-passwd" {
					a.data["passwd"] = []byte("root:x:0:0::/:/bin/bash\n")
				}
				a.data["shadow"] = []byte("root:!:::::::\nmail:" + password + ":::::::\n")
				if mode == "missing-shadow" {
					a.data["shadow"] = []byte("root:!:::::::\n")
				}
				a.data["group"] = []byte("root:x:0:\nmail:x:8:" + members + "\n")
				a.gshadow = []byte("root:*::\nmail:!:" + admins + ":" + gsMembers + "\n")
				out, e := qualifyMailParent(unix.Stat_t{Mode: unix.S_IFDIR | 02775, Gid: 8}, 0, 0, a, p)
				if want != "" {
					requireMailRefusal(t, e, "qualification_failed", want)
					return
				}
				if e != nil || len(out.Writers) != 1 || out.Writers[0] != (mailWriter{"mail", uid, gid, shell, true, sources}) {
					t.Fatal("valid writer or evidence rejected", out, e)
				}
			})
		}
	}
}

// Multiple membership paths are retained once, with sorted writer identities.
// Changing either the recorded parent metadata or writer set invalidates it.
func TestMailParentAcceptedEvidence(t *testing.T) {
	a, p := mailDatabaseFixture(), mailPolicyFixture()
	a.data["passwd"] = append(a.data["passwd"], []byte("queue:x:9:99::/nonexistent:/bin/false\n")...)
	a.data["shadow"] = append(a.data["shadow"], []byte("queue:*:::::::\n")...)
	a.data["group"] = []byte("root:x:0:\nmail:x:8:queue,mail\n")
	a.gshadow = []byte("root:*::\nmail:!:mail:mail\n")
	out, e := qualifyMailParent(unix.Stat_t{Mode: unix.S_IFDIR | 02775, Gid: 8}, 0, 0, a, p)
	if e != nil || len(out.Writers) != 2 || out.Writers[0].Name != "mail" || out.Writers[0].Sources != 15 || out.Writers[1].Name != "queue" || out.Writers[1].Sources != 2 || !out.unchanged(out) {
		t.Fatal(out, e)
	}
	other := out
	other.Metadata.Mode = unix.S_IFDIR | 0755
	if out.unchanged(other) {
		t.Fatal("metadata drift accepted")
	}
	other = out
	other.Writers = append([]mailWriter(nil), out.Writers...)
	other.Writers[0].Shell = "/bin/false"
	if out.unchanged(other) {
		t.Fatal("writer drift accepted")
	}
}

// Real protected fixture DBs and no-follow descriptor probes exercise the full
// capture/recheck path with root mapped to self and a 0755 root-group parent.
// The mail-group 2775 ownership branch is independently covered by the synthetic
// metadata controls above; no privileged chown is claimed here.
func TestMailParentProtectedObservation(t *testing.T) {
	for _, mode := range []string{"absent-control", "present", "dangling-link", "parent-mode-drift", "parent-inode-drift", "passwd-drift", "credential-drift", "database-mode-drift", "unsafe-config-ancestor", "missing-parent", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			etc := fixtureDir(t, root)
			mailPath := filepath.Join(root, "mail")
			if e := os.Mkdir(mailPath, 0755); e != nil {
				t.Fatal(e)
			}
			a := mailDatabaseFixture()
			a.data["group"] = []byte(fmt.Sprintf("root:x:%d:\nmail:x:8:\n", etc.group))
			for name, data := range a.data {
				if e := os.WriteFile(filepath.Join(root, name), data, 0600); e != nil {
					t.Fatal(e)
				}
			}
			if e := os.WriteFile(filepath.Join(root, "gshadow"), a.gshadow, 0600); e != nil {
				t.Fatal(e)
			}
			open := func(path string) (*Dir, error) {
				fd, e := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
				if e != nil {
					return nil, e
				}
				return &Dir{f: os.NewFile(uintptr(fd), path), owner: etc.owner, group: etc.group}, nil
			}
			leaf := filepath.Join(mailPath, "worker-test")
			p := mailPolicyFixture()
			if e := qualifiedMailSpoolAbsentObserved(context.Background(), etc, leaf, p, open, nil); e != nil {
				t.Fatal("positive control", e)
			}
			var hook func()
			ctx := context.Background()
			want, code := "mail_parent_changed", "qualification_failed"
			switch mode {
			case "present":
				want = "entry_present"
				if e := os.WriteFile(leaf, []byte("owned by nobody in this test"), 0600); e != nil {
					t.Fatal(e)
				}
			case "dangling-link":
				want = "entry_present"
				if e := os.Symlink("missing", leaf); e != nil {
					t.Fatal(e)
				}
			case "parent-mode-drift":
				hook = func() {
					if e := os.Chmod(mailPath, 0755|os.ModeSetgid); e != nil {
						t.Fatal(e)
					}
				}
				want = "mail_parent"
			case "parent-inode-drift":
				hook = func() {
					if e := os.Rename(mailPath, mailPath+"-old"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(mailPath, 0755); e != nil {
						t.Fatal(e)
					}
				}
			case "passwd-drift":
				hook = func() {
					data := strings.Replace(string(a.data["passwd"]), "/var/mail:", "/changed:", 1)
					if e := os.WriteFile(filepath.Join(root, "passwd"), []byte(data), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "credential-drift":
				hook = func() {
					if e := os.WriteFile(filepath.Join(root, "gshadow"), []byte("root:*::\nmail:*::\n"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			case "database-mode-drift":
				hook = func() {
					if e := os.Chmod(filepath.Join(root, "group"), 0644); e != nil {
						t.Fatal(e)
					}
				}
			case "unsafe-config-ancestor":
				etc.chainErr = refusal("unsafe_ancestor", "publication", nil)
				code = "directory_unknown"
				want = "passwd"
			case "missing-parent":
				if e := os.Remove(mailPath); e != nil {
					t.Fatal(e)
				}
			case "cancelled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			e := qualifiedMailSpoolAbsentObserved(ctx, etc, leaf, p, open, hook)
			if mode == "absent-control" {
				if e != nil {
					t.Fatal(e)
				}
				return
			}
			if mode == "cancelled" {
				if !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				return
			}
			if mode == "missing-parent" {
				if !errors.Is(e, unix.ENOENT) {
					t.Fatal(e)
				}
				return
			}
			requireMailRefusal(t, e, code, want)
			if mode == "present" || mode == "dangling-link" {
				if _, e := os.Lstat(leaf); e != nil {
					t.Fatal("mail was removed", e)
				}
			}
		})
	}
}
