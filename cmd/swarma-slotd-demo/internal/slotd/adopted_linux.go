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
// admitted object), linger off, no cron or at entries, and no kernel key
// charged to the UID. Any residue refuses.
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

// verifyAdoptedKeyFile checks the declared agent key before it is bound
// read-only into the slot: a regular file (no final symlink), owned by the
// adopted UID or root, writable by neither group nor other.
func verifyAdoptedKeyFile(id slotIdentity) error {
	var st unix.Stat_t
	if err := unix.Lstat(id.KeyFile, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || (st.Uid != id.UID && st.Uid != 0) || st.Mode&0022 != 0 || strings.ContainsRune(id.KeyFile, ':') {
		return errors.New("adopted key file refused")
	}
	return nil
}
