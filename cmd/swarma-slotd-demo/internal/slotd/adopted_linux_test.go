//go:build linux

package slotd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Proves the residue search finds a file owned by the UID anywhere below the
// root (directories included), honours exactly the admitted paths and the
// skipped directories, and never follows a symlink out of the tree. Runs as
// the invoking user over a private tree; the root suite covers the real view.
func TestAdoptedResidueSearch(t *testing.T) {
	uid := uint32(os.Getuid())
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Everything in a private tree is owned by the invoking UID; search for
	// a different UID first: nothing is found (valid neighbour).
	if found, err := findOwned(ctx, root, uid+1, nil, nil, time.Minute); err != nil || found != "" {
		t.Fatalf("foreign UID: %q %v", found, err)
	}
	found, err := findOwned(ctx, root, uid, nil, nil, time.Minute)
	if err != nil || found == "" {
		t.Fatalf("owned entry not found: %q %v", found, err)
	}
	// Admit the top-level entries and skip one directory: the search must
	// still descend into "a" and find its children.
	if found, err = findOwned(ctx, root, uid, nil, map[string]bool{filepath.Join(root, "a"): true, filepath.Join(root, "link"): true}, time.Minute); err != nil || found == "" {
		t.Fatalf("descendant not found: %q %v", found, err)
	}
	all := map[string]bool{}
	for _, p := range []string{"a", "a/b", "a/b/c", "link"} {
		all[filepath.Join(root, p)] = true
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != "" {
		t.Fatalf("admitted tree reported %q %v", found, err)
	}
	residue := filepath.Join(deep, "residue")
	if err = os.WriteFile(residue, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != residue {
		t.Fatalf("residue %q %v, want %q", found, err, residue)
	}
	if found, err = findOwned(ctx, root, uid, map[string]bool{filepath.Join(root, "a", "b"): true}, all, time.Minute); err != nil || found != "" {
		t.Fatalf("skipped directory searched: %q %v", found, err)
	}
	// The symlink target holds an owned file; it is never reached.
	if err = os.WriteFile(filepath.Join(outside, "target"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(residue); err != nil {
		t.Fatal(err)
	}
	if found, err = findOwned(ctx, root, uid, nil, all, time.Minute); err != nil || found != "" {
		t.Fatalf("symlink followed: %q %v", found, err)
	}
	// An expired search refuses instead of passing.
	expired, cancel := context.WithCancel(ctx)
	cancel()
	if found, err = findOwned(expired, root, uid+1, nil, nil, time.Minute); err == nil {
		t.Fatalf("cancelled search passed: %q", found)
	}
}

// Proves a caller account whose UID is the adopted UID is refused like a
// caller inside the slot range, while the same caller is admitted when the
// declaration names another UID. Uses the invoking (non-root) account.
func TestAdoptedCallerOverlap(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" || !userPattern.MatchString(me.Username) {
		t.Skip("needs a named non-root invoking account")
	}
	uid, _ := strconv.ParseUint(me.Uid, 10, 32)
	p := adoptedPolicy(t)
	p.CallerUser = me.Username
	decl := *p.Adopted
	decl.UID = uint32(uid) + 1
	p.Adopted = &decl
	if got, _, err := callerIdentity(p); err != nil || uint64(got) != uid {
		t.Fatalf("caller with another UID: %d %v", got, err)
	}
	decl.UID = uint32(uid)
	if _, _, err = callerIdentity(p); err == nil || err.Error() != "caller overlaps slot identities" {
		t.Fatalf("caller with the adopted UID: %v", err)
	}
}

// Proves the conservative system-crontab rule over a private /etc stand-in.
// Refused with the scheduled-entry error, in crontab and in a cron.d file:
// job lines naming the account by name, tab-separated, by UID or UID with
// leading zeros, as "@reboot name", without a command; the rev183 witnesses
// (an unterminated quoted env-prefix job line, NUL after the name, a
// vertical tab inside a time field); the account as a token outside the
// user field of an env-looking line; any byte outside printable ASCII, tab
// and newline, even in a comment (CR, DEL, UTF-8); and the stated false
// positives (an environment value, including the complete assignment
// "*= * * * * name cmd" cron does not run, or another user's command
// argument naming the account as a token). Passing neighbours: comments naming the
// account (also indented), environment lines whose value merely contains
// the name, other users, prefix-sharing names and numbers, a real cron.d
// subdirectory, and the files after each plant is removed. A symlink as
// the crontab or as a cron.d entry refuses with errSystemCronSymlink
// whatever it points to (rev184 witnesses: nothing, a directory, a file
// naming the account, a clean file, the clean cron.d/neighbours by a
// relative link).
// Refused with another error and without blocking (5 s bound): a FIFO in
// cron.d, and a FIFO, a symlink or a regular file in place of cron.d; also
// an oversized file and, when not root, an unreadable file or directory.
// The rule over-approximates cron; it is not a parser.
func TestSystemCronScheduledAs(t *testing.T) {
	const name, uid = "swarma-agent", uint32(61000)
	etc := t.TempDir()
	cronD := filepath.Join(etc, "cron.d")
	scheduled := func(step string, want error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- systemCronScheduledAs(etc, name, uid) }()
		var err error
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			// Release a reader blocked on a FIFO so the test ends.
			for _, p := range []string{cronD, filepath.Join(cronD, "fifo")} {
				if w, oerr := unix.Open(p, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); oerr == nil {
					unix.Close(w)
				}
			}
			t.Fatalf("%s: the gate blocked for 5 s instead of refusing", step)
		}
		switch {
		case want == nil && err != nil:
			t.Fatalf("%s: valid neighbour refused: %v", step, err)
		case want == errSystemCronScheduled && !errors.Is(err, errSystemCronScheduled):
			t.Fatalf("%s: %v, want the scheduled-entry refusal", step, err)
		case want != nil && want != errSystemCronScheduled && (err == nil || errors.Is(err, errSystemCronScheduled) || !strings.Contains(err.Error(), want.Error())):
			t.Fatalf("%s: %v, want a fail-closed refusal", step, err)
		}
	}
	write := func(p, b string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(etc, p), []byte(b), 0644); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(p string) {
		t.Helper()
		if err := os.Remove(filepath.Join(etc, p)); err != nil {
			t.Fatal(err)
		}
	}
	scheduled("no crontab, no cron.d", nil)
	neighbours := "SHELL=/bin/sh\nMAILTO=swarma-agent\n\"QUOTED\"=value\nCRON_TZ = UTC\nMY-VAR=swarma-agent\n\n" +
		"# 0 0 31 2 * swarma-agent /bin/true\n   # indented comment swarma-agent\n\t#swarma-agent 61000\n" +
		"17 * * * * root cd / && run-parts --report /etc/cron.hourly\n" +
		"0 0 31 2 * swarma-agent-other /bin/true\n@daily root /bin/true\n0 0 31 2 * 61001 /bin/true\n" +
		"0 0 31 2 * 610000 /bin/true\n0 0 31 2 * root /bin/echo swarma-agent: 61000x\n"
	write("crontab", neighbours)
	if err := os.Mkdir(cronD, 0755); err != nil {
		t.Fatal(err)
	}
	write("cron.d/.placeholder", "# DO NOT EDIT OR REMOVE\n")
	write("cron.d/neighbours", neighbours)
	if err := os.Mkdir(filepath.Join(cronD, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	scheduled("valid neighbours", nil)
	for _, line := range []string{
		"0 0 31 2 * swarma-agent /bin/true\n",
		"0 0 31 2 *\tswarma-agent\t/bin/true\n",
		"0 0 31 2 * 61000 /bin/true\n",
		"0 0 31 2 * 0061000 /bin/true\n",
		"@reboot swarma-agent /bin/true\n",
		"0 0 31 2 * swarma-agent\n",                                // job line without a command
		"*=\" * * * * swarma-agent /bin/true\n",                    // rev183: unterminated quoted env prefix, cron runs it
		"0 0 31 2 * swarma-agent\x00 /bin/true\n",                  // rev183: NUL after the name
		"0\v0 0 * * * swarma-agent /bin/true\n",                    // rev183: vertical tab inside a time field
		"MAILTO=\" 0 0 31 2 * swarma-agent /bin/true\n",            // env-looking line, account as its 7th field
		"-*/5 * * * * swarma-agent /bin/true\r\n",                  // CR
		"# caf\xc3\xa9\n",                                          // non-ASCII, even in a comment
		"# \x7f\n",                                                 // DEL
		"MAILTO = swarma-agent\n",                                  // false positive: environment value
		"\"QUOTED\" = swarma-agent\n",                              // false positive: quoted environment name
		"*= * * * * swarma-agent /bin/true\n",                      // false positive: complete assignment cron does not run
		"0 0 31 2 * root /bin/echo swarma-agent\n",                 // false positive: another user's argument
		"\t0 0 31 2 * root /bin/kill -9 0061000 # not a comment\n", // false positive: UID as an argument
	} {
		write("crontab", neighbours+line)
		scheduled(fmt.Sprintf("crontab %q", line), errSystemCronScheduled)
		write("crontab", neighbours)
		write("cron.d/job", line)
		scheduled(fmt.Sprintf("cron.d %q", line), errSystemCronScheduled)
		remove("cron.d/job")
	}
	scheduled("lines removed", nil)
	// rev184: a symlink as the crontab or as a cron.d entry refuses
	// whatever it points to; it is never followed. The regular files and
	// the real subdirectory above are the passing neighbours, and removing
	// each link restores the pass.
	targets := t.TempDir()
	account := filepath.Join(targets, "account")
	if err := os.WriteFile(account, []byte("0 0 31 2 * swarma-agent /bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(targets, "clean")
	if err := os.WriteFile(clean, []byte(neighbours), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(targets, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ step, target, crontabTarget string }{
		{"dangling symlink", filepath.Join(targets, "missing"), filepath.Join(targets, "missing")},
		{"symlink to a directory", filepath.Join(targets, "dir"), filepath.Join(targets, "dir")},
		{"symlink to a file naming the account", account, account},
		{"symlink to a clean file", clean, clean},
		{"relative symlink to the clean cron.d/neighbours", "neighbours", "cron.d/neighbours"},
	} {
		if err := os.Symlink(link.target, filepath.Join(cronD, "job")); err != nil {
			t.Fatal(err)
		}
		scheduled("cron.d "+link.step, errSystemCronSymlink)
		remove("cron.d/job")
		scheduled("cron.d "+link.step+" removed", nil)
		remove("crontab")
		if err := os.Symlink(link.crontabTarget, filepath.Join(etc, "crontab")); err != nil {
			t.Fatal(err)
		}
		scheduled("crontab "+link.step, errSystemCronSymlink)
		remove("crontab")
		write("crontab", neighbours)
		scheduled("crontab "+link.step+" removed", nil)
	}
	// Unknowns refuse.
	write("cron.d/bad", strings.Repeat("#", systemCronFileLimit+1))
	scheduled("oversized file", errors.New("too large"))
	remove("cron.d/bad")
	if err := unix.Mkfifo(filepath.Join(cronD, "fifo"), 0644); err != nil {
		t.Fatal(err)
	}
	scheduled("FIFO in cron.d", errors.New("not a regular file"))
	remove("cron.d/fifo")
	// cron.d itself replaced: a FIFO (rev183: must not block), a symlink to
	// the real directory, and a regular file each refuse.
	saved := filepath.Join(etc, "cron.d.saved")
	if err := os.Rename(cronD, saved); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(cronD, 0600); err != nil {
		t.Fatal(err)
	}
	scheduled("FIFO as cron.d", errors.New("cron.d: not an openable directory"))
	remove("cron.d")
	if err := os.Symlink(saved, cronD); err != nil {
		t.Fatal(err)
	}
	scheduled("symlink as cron.d", errors.New("cron.d: not an openable directory"))
	remove("cron.d")
	write("cron.d", "0 0 31 2 * root /bin/true\n")
	scheduled("regular file as cron.d", errors.New("cron.d: not an openable directory"))
	remove("cron.d")
	if err := os.Rename(saved, cronD); err != nil {
		t.Fatal(err)
	}
	scheduled("unknowns removed", nil)
	if os.Getuid() == 0 {
		t.Log("running as root: the unreadable-file and unreadable-directory cases are not exercised")
		return
	}
	if err := os.Chmod(filepath.Join(cronD, "neighbours"), 0); err != nil {
		t.Fatal(err)
	}
	scheduled("unreadable cron.d file", errors.New("permission denied"))
	if err := os.Chmod(filepath.Join(cronD, "neighbours"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cronD, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(cronD, 0755) })
	scheduled("unreadable cron.d", errors.New("permission denied"))
	if err := os.Chmod(cronD, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(etc, "crontab"), 0); err != nil {
		t.Fatal(err)
	}
	scheduled("unreadable crontab", errors.New("permission denied"))
}

// Proves the stat-to-open recheck of systemCronOpenEntry (rev184): a
// cron.d entry examined as a regular file and then, before the open,
// replaced by a symlink to that same file (only O_NOFOLLOW catches it), by a
// symlink to another file, by another regular file renamed over it (only
// the device/inode recheck catches it), by a FIFO (without blocking, 5 s
// bound) or by a directory, or removed, refuses as changed. The unchanged
// file, and a file rewritten in place (same inode), open: the valid
// neighbours, checked first.
func TestSystemCronOpenEntryChanged(t *testing.T) {
	dir := t.TempDir()
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dfd)
	job := filepath.Join(dir, "job")
	open := func(step string, replace func(), wantOpen bool) {
		t.Helper()
		if err := os.RemoveAll(job); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(job, []byte("0 0 31 2 * root /bin/true\n"), 0644); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, "job", &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			t.Fatal(err)
		}
		replace()
		done := make(chan error, 1)
		go func() {
			f, err := systemCronOpenEntry(dfd, "job", job, &st)
			if f != nil {
				f.Close()
			}
			done <- err
		}()
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			if w, oerr := unix.Open(job, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); oerr == nil {
				unix.Close(w)
			}
			t.Fatalf("%s: the open blocked for 5 s instead of refusing", step)
		}
		if wantOpen && err != nil {
			t.Fatalf("%s: valid neighbour refused: %v", step, err)
		}
		if !wantOpen && (err == nil || !strings.Contains(err.Error(), "changed after it was examined")) {
			t.Fatalf("%s: %v, want the changed-entry refusal", step, err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	open("unchanged", func() {}, true)
	open("rewritten in place", func() { must(os.WriteFile(job, []byte("# other\n"), 0644)) }, true)
	open("symlink to the same file", func() {
		must(os.Rename(job, job+".real"))
		must(os.Symlink(job+".real", job))
	}, false)
	open("symlink to another file", func() {
		must(os.WriteFile(job+".other", []byte("0 0 31 2 * root /bin/true\n"), 0644))
		must(os.Remove(job))
		must(os.Symlink(job+".other", job))
	}, false)
	open("another regular file renamed over it", func() {
		must(os.WriteFile(job+".new", []byte("0 0 31 2 * root /bin/true\n"), 0644))
		must(os.Rename(job+".new", job))
	}, false)
	open("FIFO", func() {
		must(os.Remove(job))
		must(unix.Mkfifo(job, 0644))
	}, false)
	open("directory", func() {
		must(os.Remove(job))
		must(os.Mkdir(job, 0755))
	}, false)
	open("removed", func() { must(os.Remove(job)) }, false)
}

// Proves the key-path rule portably: a root-owned key under root-owned,
// non-writable ancestors (/etc/passwd stands in) is admitted, while a key
// whose ancestry includes a directory owned by the invoking (non-root)
// account is refused as ancestry, even though the key file itself is
// acceptable; a relative or ':'-bearing path is refused. The root suite
// covers writable, foreign-owned and symlinked components.
func TestAdoptedKeyAncestry(t *testing.T) {
	id := slotIdentity{UID: 61000, SocketGID: 61001, KeyFile: "/etc/passwd"}
	if err := verifyAdoptedKeyFile(id); err != nil {
		t.Fatalf("root-owned key path refused: %v", err)
	}
	if os.Getuid() == 0 {
		t.Log("running as root: the non-root-owned ancestor case is covered by TestRootAdoptedKeyAncestry")
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	id.UID = uint32(os.Getuid())
	id.KeyFile = filepath.Join(dir, "agent.key")
	if err := os.WriteFile(id.KeyFile, []byte("fixture agent key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAdoptedKeyFile(id); err == nil || !strings.Contains(err.Error(), "ancestry") {
		t.Fatalf("non-root-owned ancestor: %v", err)
	}
	for _, bad := range []string{"agent.key", "/etc/pass:wd"} {
		id.KeyFile = bad
		if err := verifyAdoptedKeyFile(id); err == nil {
			t.Fatalf("%q admitted", bad)
		}
	}
}
