//go:build linux

package slotd

import (
	"context"
	"errors"
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

// Proves the system-crontab reader over a private /etc stand-in: a job line
// scheduled as the account (by name, by numeric UID, with leading zeros, or
// as "@keyword name") in crontab or in any cron.d file refuses with the
// scheduled-entry error, while comments, environment lines (also quoted,
// with blanks around "=", and with a non-identifier name), other users, a prefix-sharing user and a cron.d
// subdirectory pass; a symlinked cron.d file is followed as cron does. An
// unparsable job line, a FIFO (without blocking), an oversized file and
// (when not root) an unreadable file or directory refuse with another error.
func TestSystemCronScheduledAs(t *testing.T) {
	const name, uid = "swarma-agent", uint32(61000)
	etc := t.TempDir()
	scheduled := func(step string, want error) {
		t.Helper()
		err := systemCronScheduledAs(etc, name, uid)
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
	scheduled("no crontab, no cron.d", nil)
	neighbours := "SHELL=/bin/sh\nMAILTO=swarma-agent\n\"QUOTED\" = swarma-agent\nCRON_TZ = UTC\nMY-VAR=swarma-agent\n\n" +
		"# 0 0 31 2 * swarma-agent /bin/true\n   # indented comment swarma-agent\n" +
		"17 * * * * root cd / && run-parts --report /etc/cron.hourly\n" +
		"0 0 31 2 * swarma-agent-other /bin/true\n@daily root /bin/true\n0 0 31 2 * 61001 /bin/true\n"
	write("crontab", neighbours)
	if err := os.Mkdir(filepath.Join(etc, "cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	write("cron.d/.placeholder", "# DO NOT EDIT OR REMOVE\n")
	write("cron.d/neighbours", neighbours)
	if err := os.Mkdir(filepath.Join(etc, "cron.d", "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	scheduled("valid neighbours", nil)
	for _, line := range []string{"0 0 31 2 * swarma-agent /bin/true", "0 0 31 2 *\tswarma-agent\t/bin/true", "0 0 31 2 * 61000 /bin/true", "0 0 31 2 * 0061000 /bin/true", "@reboot swarma-agent /bin/true", "-*/5 * * * * swarma-agent /bin/true\r"} {
		write("crontab", neighbours+line+"\n")
		scheduled("crontab "+line, errSystemCronScheduled)
		write("crontab", neighbours)
		write("cron.d/job", line+"\n")
		scheduled("cron.d "+line, errSystemCronScheduled)
		if err := os.Remove(filepath.Join(etc, "cron.d", "job")); err != nil {
			t.Fatal(err)
		}
	}
	scheduled("lines removed", nil)
	// A symlinked cron.d entry is read through, as cron reads it.
	target := filepath.Join(t.TempDir(), "job")
	if err := os.WriteFile(target, []byte("0 0 31 2 * swarma-agent /bin/true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(etc, "cron.d", "linked")); err != nil {
		t.Fatal(err)
	}
	scheduled("symlinked cron.d file", errSystemCronScheduled)
	if err := os.Remove(filepath.Join(etc, "cron.d", "linked")); err != nil {
		t.Fatal(err)
	}
	// Unknowns refuse.
	write("cron.d/bad", "0 0 31 2 * swarma-agent\n")
	scheduled("job line without a command", errors.New("unparsable"))
	write("cron.d/bad", strings.Repeat("#", systemCronFileLimit+1))
	scheduled("oversized file", errors.New("too large"))
	if err := os.Remove(filepath.Join(etc, "cron.d", "bad")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(etc, "cron.d", "fifo"), 0644); err != nil {
		t.Fatal(err)
	}
	scheduled("FIFO", errors.New("not a regular file"))
	if err := os.Remove(filepath.Join(etc, "cron.d", "fifo")); err != nil {
		t.Fatal(err)
	}
	scheduled("unknowns removed", nil)
	if os.Getuid() == 0 {
		t.Log("running as root: the unreadable-file and unreadable-directory cases are not exercised")
		return
	}
	if err := os.Chmod(filepath.Join(etc, "cron.d", "neighbours"), 0); err != nil {
		t.Fatal(err)
	}
	scheduled("unreadable cron.d file", errors.New("permission denied"))
	if err := os.Chmod(filepath.Join(etc, "cron.d", "neighbours"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(etc, "cron.d"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(etc, "cron.d"), 0755) })
	scheduled("unreadable cron.d", errors.New("permission denied"))
	if err := os.Chmod(filepath.Join(etc, "cron.d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(etc, "crontab"), 0); err != nil {
		t.Fatal(err)
	}
	scheduled("unreadable crontab", errors.New("permission denied"))
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
