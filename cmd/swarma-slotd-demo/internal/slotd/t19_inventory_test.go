package slotd

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// T19.1 certifies the slot's reachable pathname-socket set from two walks of
// the SAME mount view: the slot UID's own walk (what the payload can list) and
// root's walk through /proc/<slot pid>/root (what the view holds, whatever the
// slot UID may list). Every traversal failure keeps its path and errno; an
// omitted subtree is accepted only with a stated reason, never by count.

// t19WalkError is one failed directory traversal. Search is the errno of
// stat(Path + "/.") by the same walker: EACCES means that walker's UID cannot
// resolve ANY name below Path, so no pathname connect can pass through it.
type t19WalkError struct {
	Path   string
	Errno  string
	Search string `json:",omitempty"`
}

// t19Mount is one /proc/<pid>/mountinfo entry of the slot's view. The walker
// fills File (the mount point resolves to a non-directory, so nothing lies
// below it) and Unreachable (the mount point does not resolve in this view,
// e.g. a host mount shadowed by a tmpfs, so no path reaches its contents).
type t19Mount struct {
	Point, FSType     string
	File, Unreachable bool
}

// t19ViewInventory is root's walk of the slot's view. Pruned lists the mount
// points not walked because they and every mount below them are socketless.
type t19ViewInventory struct {
	Sockets []string
	Errors  []t19WalkError
	Pruned  []string
	Mounts  []t19Mount
}

// t19SocketlessFS are filesystem types whose directories have no mknod
// operation, so bind(2) of an AF_UNIX pathname socket fails there (EPERM):
// no socket inode can exist on them. Unknown types count as socket-capable.
var t19SocketlessFS = map[string]bool{"proc": true, "sysfs": true, "cgroup2": true, "cgroup": true, "debugfs": true, "tracefs": true, "securityfs": true, "pstore": true, "bpf": true, "configfs": true, "efivarfs": true, "fusectl": true, "binfmt_misc": true, "autofs": true, "mqueue": true, "devpts": true}

// parseT19Mountinfo reads mount point (field 5, octal-escaped) and fstype
// (first field after " - ") of every line. A malformed line is an error.
func parseT19Mountinfo(b []byte) ([]t19Mount, error) {
	var mounts []t19Mount
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		head, tail, ok := strings.Cut(line, " - ")
		fields, after := strings.Fields(head), strings.Fields(tail)
		if !ok || len(fields) < 6 || len(after) < 1 {
			return nil, errors.New("malformed mountinfo line: " + strconv.Quote(line))
		}
		point, err := unescapeT19Mount(fields[4])
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, t19Mount{Point: point, FSType: after[0]})
	}
	if len(mounts) == 0 {
		return nil, errors.New("empty mountinfo")
	}
	return mounts, nil
}

func unescapeT19Mount(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", errors.New("bad mountinfo escape: " + strconv.Quote(s))
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", errors.New("bad mountinfo escape: " + strconv.Quote(s))
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}

func t19Below(path, dir string) bool {
	return dir == "/" || path == dir || strings.HasPrefix(path, dir+"/")
}

// t19SocketlessSubtree holds when the directory mount containing dir and
// every reachable directory mount at or below dir have socketless types. A
// file mount below dir holds only its own inode, which the walker lstats.
func t19SocketlessSubtree(mounts []t19Mount, dir string) bool {
	container := ""
	for _, m := range mounts {
		if !m.Unreachable && !m.File && t19Below(dir, m.Point) && len(m.Point) >= len(container) {
			container = m.Point
		}
	}
	if container == "" {
		return false
	}
	for _, m := range mounts {
		if m.Unreachable || t19SocketlessFS[m.FSType] {
			continue
		}
		if m.Point == container || (t19Below(m.Point, dir) && !(m.File && m.Point != dir)) {
			return false
		}
	}
	return true
}

// t19InventoryVerdict returns the slot's reachable pathname sockets and every
// reason the certification is refused. Rules:
//   - root's view walk must be complete: each error and prune lies in a
//     socketless subtree by the view's mount facts;
//   - each slot omission carries path and errno and is either unsearchable for
//     the slot UID (nothing below resolves) or holds no socket in root's view;
//   - every socket in the view is listed by the slot or lies below an
//     unsearchable omission; every socket the slot lists is in the view.
func t19InventoryVerdict(view t19ViewInventory, slotSockets []string, slotOmitted []t19WalkError) ([]string, []string) {
	var problems []string
	if len(view.Mounts) == 0 {
		problems = append(problems, "root view: no mount facts")
	}
	for _, e := range view.Errors {
		if e.Path == "" || e.Errno == "" || !t19SocketlessSubtree(view.Mounts, e.Path) {
			problems = append(problems, "root view incomplete: "+strconv.Quote(e.Path)+" "+e.Errno)
		}
	}
	for _, p := range view.Pruned {
		if !t19SocketlessSubtree(view.Mounts, p) {
			problems = append(problems, "root view pruned a socket-capable subtree: "+strconv.Quote(p))
		}
	}
	var unsearchable []string
	for _, e := range slotOmitted {
		if e.Path == "" || e.Errno == "" || e.Search == "" {
			problems = append(problems, "slot omission without path, errno or search fact: "+strconv.Quote(e.Path)+" "+e.Errno+" "+e.Search)
			continue
		}
		if e.Search == "EACCES" {
			unsearchable = append(unsearchable, e.Path)
			continue
		}
		for _, s := range view.Sockets {
			if t19Below(s, e.Path) {
				problems = append(problems, "slot omitted searchable "+strconv.Quote(e.Path)+" ("+e.Errno+") holding socket "+strconv.Quote(s))
			}
		}
	}
	var reachable []string
	for _, s := range view.Sockets {
		if slices.ContainsFunc(unsearchable, func(dir string) bool { return t19Below(s, dir) }) {
			continue
		}
		reachable = append(reachable, s)
		if !slices.Contains(slotSockets, s) {
			problems = append(problems, "socket "+strconv.Quote(s)+" in the view is missing from the slot's inventory")
		}
	}
	for _, s := range slotSockets {
		if !slices.Contains(view.Sockets, s) {
			problems = append(problems, "slot lists "+strconv.Quote(s)+", which root's view walk lacks")
		}
	}
	slices.Sort(reachable)
	return reachable, problems
}

// Proves the T19.1 certification refuses each incomplete or inconsistent
// inventory shape beside an accepted control, and that an unsearchable
// omission is the only way a viewed socket leaves the reachable set. Pure
// function over fixture inventories; the kernel side is TestRootT19InventoryOmission.
func TestT19InventoryVerdict(t *testing.T) {
	const wallet = "/run/swarma-wallet/wallet.sock"
	mounts := []t19Mount{{Point: "/", FSType: "ext4"}, {Point: "/proc", FSType: "proc"}, {Point: "/proc/sys/fs/binfmt_misc", FSType: "autofs"}, {Point: "/sys", FSType: "sysfs"}, {Point: "/sys/fs/cgroup", FSType: "cgroup2"}, {Point: "/run", FSType: "tmpfs"}, {Point: "/run/swarma-wallet", FSType: "tmpfs"}, {Point: "/opt", FSType: "ext4"}}
	base := func() (t19ViewInventory, []string, []t19WalkError) {
		return t19ViewInventory{Sockets: []string{wallet}, Errors: []t19WalkError{{Path: "/sys/kernel/x", Errno: "ENOENT"}}, Pruned: []string{"/proc", "/sys"}, Mounts: mounts},
			[]string{wallet},
			[]t19WalkError{{"/etc/ssl/private", "EACCES", "EACCES"}, {"/opt/unlistable", "EACCES", "ok"}, {"/sys/kernel/debug", "EACCES", "EACCES"}}
	}
	view, slot, omitted := base()
	if reachable, problems := t19InventoryVerdict(view, slot, omitted); len(problems) != 0 || !slices.Equal(reachable, []string{wallet}) {
		t.Fatalf("complete control refused: %q %q", reachable, problems)
	}
	// An unsearchable omission removes its sockets from the reachable set
	// (the inaccessible positive neighbour) without a problem.
	view.Sockets = append(view.Sockets, "/etc/ssl/private/ctl.sock")
	if reachable, problems := t19InventoryVerdict(view, slot, omitted); len(problems) != 0 || !slices.Equal(reachable, []string{wallet}) {
		t.Fatalf("unsearchable neighbour: %q %q", reachable, problems)
	}
	for name, c := range map[string]struct {
		edit func(*t19ViewInventory, *[]string, *[]t19WalkError)
		want string
	}{
		"searchable omission holds a socket": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Sockets = append(v.Sockets, "/opt/unlistable/ctl.sock")
		}, `slot omitted searchable "/opt/unlistable" (EACCES) holding socket "/opt/unlistable/ctl.sock"`},
		"omission without search fact": {func(_ *t19ViewInventory, _ *[]string, o *[]t19WalkError) {
			*o = append(*o, t19WalkError{Path: "/srv/x", Errno: "EACCES"})
		}, "slot omission without path, errno or search fact"},
		"omission without errno": {func(_ *t19ViewInventory, _ *[]string, o *[]t19WalkError) {
			*o = append(*o, t19WalkError{Path: "/srv/x", Search: "EACCES"})
		}, "slot omission without path, errno or search fact"},
		"omission without path": {func(_ *t19ViewInventory, _ *[]string, o *[]t19WalkError) {
			*o = append(*o, t19WalkError{Errno: "EACCES", Search: "EACCES"})
		}, "slot omission without path, errno or search fact"},
		"root view error on a socket-capable mount": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Errors = append(v.Errors, t19WalkError{Path: "/opt/fuse", Errno: "EACCES"})
		}, `root view incomplete: "/opt/fuse" EACCES`},
		"root view error under a socketless mount with a capable submount": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Mounts = append(slices.Clone(v.Mounts), t19Mount{Point: "/sys/kernel/x/run", FSType: "tmpfs"})
		}, `root view incomplete: "/sys/kernel/x" ENOENT`},
		"root view pruned a capable subtree": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Pruned = append(v.Pruned, "/run")
		}, `root view pruned a socket-capable subtree: "/run"`},
		"root view without mount facts": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Mounts = nil
		}, "root view: no mount facts"},
		"view socket the slot did not list": {func(v *t19ViewInventory, _ *[]string, _ *[]t19WalkError) {
			v.Sockets = append(v.Sockets, "/usr/share/x.sock")
		}, `socket "/usr/share/x.sock" in the view is missing from the slot's inventory`},
		"slot socket the view lacks": {func(_ *t19ViewInventory, s *[]string, _ *[]t19WalkError) {
			*s = append(*s, "/tmp/x.sock")
		}, `slot lists "/tmp/x.sock", which root's view walk lacks`},
	} {
		t.Run(name, func(t *testing.T) {
			view, slot, omitted := base()
			c.edit(&view, &slot, &omitted)
			_, problems := t19InventoryVerdict(view, slot, omitted)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, c.want) }) {
				t.Fatalf("problems %q lack %q", problems, c.want)
			}
		})
	}
}

// Proves mountinfo parsing keeps escaped mount points exact and refuses
// malformed input instead of returning a partial mount table.
func TestT19Mountinfo(t *testing.T) {
	good := "22 1 0:21 / / rw - ext4 /dev/root rw\n36 22 0:5 / /proc rw,nosuid shared:5 - proc proc rw\n40 22 0:30 / /opt/a\\040b rw - tmpfs tmpfs rw\n"
	mounts, err := parseT19Mountinfo([]byte(good))
	if err != nil || !slices.Equal(mounts, []t19Mount{{Point: "/", FSType: "ext4"}, {Point: "/proc", FSType: "proc"}, {Point: "/opt/a b", FSType: "tmpfs"}}) {
		t.Fatalf("%+v %v", mounts, err)
	}
	for _, bad := range []string{"", "22 1 0:21 / / rw ext4 /dev/root rw", "22 1 0:21 / /a\\04 rw - ext4 x rw", "22 1 0:21 / /a\\09x rw - ext4 x rw", "22 1 / rw - ext4 x"} {
		if _, err := parseT19Mountinfo([]byte(bad)); err == nil {
			t.Errorf("malformed mountinfo %q admitted", bad)
		}
	}
	if !t19SocketlessSubtree(mounts, "/proc/sys") || t19SocketlessSubtree(mounts, "/opt") || t19SocketlessSubtree(nil, "/proc") {
		t.Fatal("socketless subtree classification")
	}
	// A capable FILE mount below /proc (systemd's inaccessible binds over
	// /proc/kcore) or an unreachable capable mount does not stop the prune;
	// a reachable capable directory mount below it does.
	for _, c := range []struct {
		extra t19Mount
		want  bool
	}{
		{t19Mount{Point: "/proc/kcore", FSType: "tmpfs", File: true}, true},
		{t19Mount{Point: "/proc/x", FSType: "tmpfs", Unreachable: true}, true},
		{t19Mount{Point: "/proc/x", FSType: "tmpfs"}, false},
		{t19Mount{Point: "/proc", FSType: "tmpfs"}, false},
	} {
		if got := t19SocketlessSubtree(append(slices.Clone(mounts), c.extra), "/proc"); got != c.want {
			t.Errorf("%+v: socketless /proc = %v, want %v", c.extra, got, c.want)
		}
	}
}
