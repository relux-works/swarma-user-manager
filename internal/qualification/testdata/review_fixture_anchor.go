package linuxos

import (
	"golang.org/x/sys/unix"
	"os"
)

// Reviewer-only overlay fixture anchor. It maps owner/group to this unprivileged
// runner exactly as fixtureDir does; every publication/storage method is unchanged.
func ReviewFixtureAnchor(path string) (*Dir, error) {
	fd, e := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if e != nil {
		return nil, e
	}
	return &Dir{f: os.NewFile(uintptr(fd), "review-fixture"), owner: uint32(os.Getuid()), group: uint32(os.Getgid())}, nil
}
