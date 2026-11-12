//go:build linux

package slotd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"golang.org/x/sys/unix"
)

// residueSearchLimit bounds one whole-view search. Exceeding it refuses
// reuse: an unfinished search proves nothing.
var residueSearchLimit = 5 * time.Minute

// adoptedNoResidue is the retirement no-residue gate (adoption condition 10).
// It runs at the end of every adopted retirement and again before every
// adoption, so the account is reused only when the previous rental left:
// no process of the UID, no file owned by the UID outside the per-slot home
// (whole-view search, /proc excluded; the declared key file is the one
// admitted object), linger off, no cron or at entries (the per-user spool,
// and any /etc/crontab or /etc/cron.d line scheduled as the account,
// whoever owns the file), and no kernel key charged to the UID. Any residue
// refuses.
func adoptedNoResidue(ctx context.Context, id slotIdentity) error {
	if !id.adopted() {
		return errors.New("no-residue gate needs an adopted identity")
	}
	proc, err := linuxos.OpenProc()
	if err != nil {
		return err
	}
	processes, err := proc.Processes(ctx, id.UID, 100000)
	closeErr := proc.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(processes) != 0 {
		return errors.New("adopted UID processes remain")
	}
	if present, err := entryPresent("/var/lib/systemd/linger/" + id.Name); err != nil || present {
		return errors.Join(err, errors.New("adopted account linger enabled"))
	}
	for _, spool := range []string{"/var/spool/cron/crontabs/", "/var/spool/cron/", "/var/spool/cron/tabs/"} {
		if present, err := entryPresent(spool + id.Name); err != nil || present {
			return errors.Join(err, errors.New("adopted account cron entry remains"))
		}
	}
	if err = systemCronScheduledAs("/etc", id.Name, id.UID); err != nil {
		return err
	}
	if err = keysCharged(id.UID); err != nil {
		return err
	}
	// at(1) jobs are files owned by the submitting UID in the at spool; the
	// whole-view search below finds them with every other owned file.
	found, err := findOwned(ctx, "/", id.UID, map[string]bool{"/proc": true, id.Home: true}, map[string]bool{id.KeyFile: true, id.Home: true}, residueSearchLimit)
	if err != nil {
		return err
	}
	if found != "" {
		return fmt.Errorf("adopted UID residue file: %s", found)
	}
	return nil
}

// entryPresent reports a non-directory entry at p (a directory of the same
// name is an unrelated spool layout, not an entry for this account).
func entryPresent(p string) (bool, error) {
	var st unix.Stat_t
	err := unix.Lstat(p, &st)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Mode&unix.S_IFMT != unix.S_IFDIR, nil
}

// keysCharged refuses when /proc/key-users lists the UID: some key or
// keyring is still charged to it. Stricter than "keyrings empty" (an empty
// persistent user keyring also refuses), never weaker.
func keysCharged(uid uint32) error {
	f, err := os.Open("/proc/key-users")
	if err != nil {
		return err
	}
	defer f.Close()
	want := strconv.FormatUint(uint64(uid), 10) + ":"
	s := bufio.NewScanner(io.LimitReader(f, 4<<20))
	for s.Scan() {
		if fields := bytes.Fields(s.Bytes()); len(fields) > 0 && string(fields[0]) == want {
			return errors.New("adopted UID kernel keys remain")
		}
	}
	return s.Err()
}

// findOwned walks the daemon's whole mount view below root without following
// symlinks and returns the first path owned by uid that is not in allow.
// Directories in skip are not entered. Vanishing entries are skipped; any
// other error, the depth bound or the time limit refuses (fail closed).
func findOwned(ctx context.Context, root string, uid uint32, skip, allow map[string]bool, limit time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var (
		mu    sync.Mutex
		found string
		fail  error
		wg    sync.WaitGroup
	)
	stop := func(p string, err error) {
		mu.Lock()
		if found == "" && fail == nil {
			found, fail = p, err
		}
		mu.Unlock()
		cancel()
	}
	sem := make(chan struct{}, 8)
	var visit func(dir string, depth int)
	visit = func(dir string, depth int) {
		defer wg.Done()
		if ctx.Err() != nil {
			return
		}
		if depth > 256 {
			stop("", errors.New("residue search depth limit"))
			return
		}
		fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) {
			return
		}
		if err != nil {
			stop("", fmt.Errorf("residue search %s: %w", dir, err))
			return
		}
		f := os.NewFile(uintptr(fd), dir)
		defer f.Close()
		for ctx.Err() == nil {
			names, rerr := f.Readdirnames(1024)
			for _, name := range names {
				p := path.Join(dir, name)
				var st unix.Stat_t
				if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					stop("", fmt.Errorf("residue search %s: %w", p, err))
					return
				}
				if st.Uid == uid && !allow[p] {
					stop(p, nil)
					return
				}
				if st.Mode&unix.S_IFMT == unix.S_IFDIR && !skip[p] {
					wg.Add(1)
					select {
					case sem <- struct{}{}:
						go func() {
							defer func() { <-sem }()
							visit(p, depth+1)
						}()
					default:
						visit(p, depth+1)
					}
				}
			}
			if errors.Is(rerr, io.EOF) || (rerr == nil && len(names) == 0) {
				return
			}
			if rerr != nil {
				if errors.Is(rerr, unix.ENOENT) {
					return
				}
				stop("", fmt.Errorf("residue search %s: %w", dir, rerr))
				return
			}
		}
	}
	wg.Add(1)
	visit(root, 0)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if fail != nil || found != "" {
		return found, fail
	}
	if err := ctx.Err(); err != nil {
		return "", errors.New("residue search incomplete")
	}
	return "", nil
}

// verifyAdoptedKeyFile checks the declared agent key at adoption and again
// before it is bound read-only into the slot: every directory from / to the
// key is root-owned, writable by neither group nor other, and no component
// is a symlink (verifyKeyAncestry); the key itself is a regular file (no
// final symlink), owned by the adopted UID or root, writable by neither
// group nor other.
func verifyAdoptedKeyFile(id slotIdentity) error {
	if !cleanAbsolutePath(id.KeyFile) || strings.ContainsRune(id.KeyFile, ':') {
		return errors.New("adopted key file refused")
	}
	parent, err := verifyKeyAncestry(path.Dir(id.KeyFile))
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	var st unix.Stat_t
	if err := unix.Fstatat(parent, path.Base(id.KeyFile), &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || (st.Uid != id.UID && st.Uid != 0) || st.Mode&0022 != 0 {
		return errors.New("adopted key file refused")
	}
	return nil
}

// verifyKeyAncestry walks dir from / one component at a time without
// following symlinks and returns an O_PATH descriptor of dir. Every
// directory on the way, / and dir included, must be a directory owned by
// root and writable by neither group nor other, so no account but root can
// replace, redirect or add a component of the key path. The frozen G2
// render declares only the key path (agent_key_file), no owner for its
// directories, so no other owner is admitted.
func verifyKeyAncestry(dir string) (int, error) {
	check := func(fd int, p string) error {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return fmt.Errorf("adopted key ancestry refused: %s", p)
		}
		return nil
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err = check(fd, "/"); err != nil {
		unix.Close(fd)
		return -1, err
	}
	walked := ""
	for _, name := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if name == "" {
			continue
		}
		walked += "/" + name
		// O_PATH|O_NOFOLLOW opens a final symlink itself; check refuses it.
		next, err := unix.Openat(fd, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("adopted key ancestry %s: %w", walked, err)
		}
		fd = next
		if err = check(fd, walked); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// System crontab bounds: a larger file or directory is an unknown, and an
// unknown refuses.
const (
	systemCronFileLimit    = 1 << 20
	systemCronEntriesLimit = 4096
)

// errSystemCronScheduled is the refusal for a system-crontab job that runs
// as the adopted account.
var errSystemCronScheduled = errors.New("adopted account system cron entry remains")

// systemCronScheduledAs refuses when <etc>/crontab or any file in
// <etc>/cron.d schedules a job as the account, by name or numeric UID, in
// the user field of the system crontab format. The file owner is
// irrelevant: a root-owned line naming the account is residue. A missing
// crontab or cron.d is no entry; a subdirectory of cron.d is ignored (cron
// does not read it); every other unreadable, oversized, non-regular or
// unparsable entry refuses (fail closed).
func systemCronScheduledAs(etc, name string, uid uint32) error {
	if err := systemCronFileScheduledAs(path.Join(etc, "crontab"), name, uid, false); err != nil {
		return err
	}
	dir := path.Join(etc, "cron.d")
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("system cron %s: %w", dir, err)
	}
	names, err := f.Readdirnames(systemCronEntriesLimit + 1)
	f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("system cron %s: %w", dir, err)
	}
	if len(names) > systemCronEntriesLimit {
		return fmt.Errorf("system cron %s: too many entries", dir)
	}
	for _, n := range names {
		if err := systemCronFileScheduledAs(path.Join(dir, n), name, uid, true); err != nil {
			return err
		}
	}
	return nil
}

// systemCronFileScheduledAs reads one system crontab (following a symlink,
// as cron does) without blocking on a FIFO and checks its user fields. A
// directory inside cron.d (dirEntry) is not read by cron and is skipped.
func systemCronFileScheduledAs(p, name string, uid uint32, dirEntry bool) error {
	var st unix.Stat_t
	err := unix.Stat(p, &st)
	if errors.Is(err, unix.ENOENT) {
		return nil // absent, vanished or dangling: no schedule
	}
	if err != nil {
		return fmt.Errorf("system cron %s: %w", p, err)
	}
	if dirEntry && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		return nil
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("system cron %s: not a regular file", p)
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("system cron %s: %w", p, err)
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.Join(err, fmt.Errorf("system cron %s: not a regular file", p))
	}
	b, err := io.ReadAll(io.LimitReader(f, systemCronFileLimit+1))
	if err != nil {
		return fmt.Errorf("system cron %s: %w", p, err)
	}
	if len(b) > systemCronFileLimit {
		return fmt.Errorf("system cron %s: too large", p)
	}
	users, err := systemCronUsers(b)
	if err != nil {
		return fmt.Errorf("system cron %s: %w", p, err)
	}
	for _, u := range users {
		if u == name {
			return errSystemCronScheduled
		}
		if n, err := strconv.ParseUint(u, 10, 32); err == nil && uint32(n) == uid {
			return errSystemCronScheduled
		}
	}
	return nil
}

// systemCronUsers returns the user field of every job line of a system
// crontab: blank lines, comments and environment assignments (NAME=value,
// spaces around "=" allowed, NAME optionally quoted) are skipped; "@keyword
// user command" and "m h dom mon dow user command" are job lines. A job line
// without a command field is unparsable and refuses.
func systemCronUsers(b []byte) ([]string, error) {
	var users []string
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || systemCronAssignment(line) {
			continue
		}
		fields := strings.Fields(line)
		want := 7
		if line[0] == '@' {
			want = 3
		}
		if len(fields) < want {
			return nil, fmt.Errorf("line %d: unparsable job line", i+1)
		}
		users = append(users, fields[want-2])
	}
	return users, nil
}

// systemCronAssignment reports a crontab environment line: an optionally
// quoted name, optional blanks, then "=".
func systemCronAssignment(line string) bool {
	rest := line
	if q := line[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(line[1:], q)
		if end < 0 {
			return false
		}
		rest = line[end+2:]
	} else {
		n := strings.IndexFunc(line, func(r rune) bool {
			return !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
		})
		if n <= 0 {
			return false
		}
		rest = line[n:]
	}
	return strings.HasPrefix(strings.TrimLeft(rest, " \t"), "=")
}
