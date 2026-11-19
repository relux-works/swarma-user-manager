//go:build linux

package identities

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func Read(directory *os.File, owner, group uint32, journalHead string) (Document, error) {
	var empty Document
	fd, err := unix.Openat(int(directory.Fd()), "identities.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return empty, ErrMismatch
	}
	file := os.NewFile(uintptr(fd), "identities.json")
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != owner || stat.Gid != group || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0644 || stat.Nlink != 1 {
		file.Close()
		return empty, ErrMismatch
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, err = unix.Fgetxattr(fd, attribute, nil); !errors.Is(err, syscall.ENODATA) {
			file.Close()
			return empty, ErrMismatch
		}
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return empty, ErrMismatch
	}
	return Decode(raw, journalHead)
}
