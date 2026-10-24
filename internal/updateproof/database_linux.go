//go:build linux

package updateproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sort"
)

// databaseDigest binds every database file and directory, including status,
// ownership/checksum metadata, diversions, triggers and pending updates. Only
// the two root lock files are excluded; locking is a separate live capability.
// Symlinks, unsafe metadata and over-budget/deep trees refuse rather than omit.
func databaseDigest(ctx context.Context, d *os.File, owner uint32, l Limits) (string, error) {
	h := sha256.New()
	var total int64
	count := 0
	var walk func(*os.File, string, int) error
	walk = func(dir *os.File, prefix string, depth int) error {
		if depth > 8 || ctx.Err() != nil || protected(dir, owner, true) != nil {
			return ErrGap
		}
		fd, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrGap
		}
		listing := os.NewFile(uintptr(fd), "database")
		names, e := listing.Readdirnames(l.Entries + 1)
		listing.Close()
		if e != nil && e != io.EOF || len(names) > l.Entries {
			return ErrGap
		}
		sort.Strings(names)
		for _, name := range names {
			if prefix == "" && (name == "lock" || name == "lock-frontend") {
				continue
			}
			count++
			if count > l.Entries || ctx.Err() != nil {
				return ErrGap
			}
			var before unix.Stat_t
			if unix.Fstatat(int(dir.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Uid != owner || before.Mode&0022 != 0 {
				return ErrGap
			}
			kind := before.Mode & unix.S_IFMT
			if kind != unix.S_IFREG && kind != unix.S_IFDIR {
				return ErrGap
			}
			flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
			if kind == unix.S_IFDIR {
				flags |= unix.O_DIRECTORY
			}
			fd, e := unix.Openat(int(dir.Fd()), name, flags, 0)
			if e != nil {
				return ErrGap
			}
			f := os.NewFile(uintptr(fd), name)
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Dev != before.Dev || st.Ino != before.Ino || st.Mode != before.Mode || st.Uid != before.Uid || st.Gid != before.Gid {
				f.Close()
				return ErrGap
			}
			for _, x := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
				if _, e := unix.Fgetxattr(fd, x, nil); e != unix.ENODATA {
					f.Close()
					return ErrGap
				}
			}
			row := struct {
				Path           string
				Mode, UID, GID uint32
				Bytes          int64
			}{prefix + name, st.Mode, st.Uid, st.Gid, 0}
			if kind == unix.S_IFDIR {
				b, _ := json.Marshal(row)
				h.Write(b)
				e = walk(f, prefix+name+"/", depth+1)
			} else {
				if st.Nlink != 1 || st.Size < 0 || st.Size > l.Bytes-total {
					f.Close()
					return ErrGap
				}
				data, err := io.ReadAll(io.LimitReader(f, l.Bytes-total+1))
				total += int64(len(data))
				if err != nil || total > l.Bytes || int64(len(data)) != st.Size {
					f.Close()
					return ErrGap
				}
				row.Bytes = int64(len(data))
				b, _ := json.Marshal(row)
				h.Write(b)
				h.Write(data)
			}
			f.Close()
			if e != nil {
				return e
			}
		}
		return nil
	}
	if !l.valid() {
		return "", ErrGap
	}
	if e := walk(d, "", 0); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
