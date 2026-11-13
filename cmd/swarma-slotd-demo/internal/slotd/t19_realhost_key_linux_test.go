//go:build linux

package slotd

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func t19KeyMetadata(st unix.Stat_t, uid uint32) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uid || st.Gid != uid || st.Nlink != 1 {
		return errors.New("probe agent key must be UID:UID 0600 regular single-link, matching the real-run shape")
	}
	return nil
}
func t19VerifyKey(id slotIdentity) error {
	if err := verifyAdoptedKeyFile(id); err != nil {
		return err
	}
	for parent := filepath.Dir(id.KeyFile); ; parent = filepath.Dir(parent) {
		f, err := openTrustedDir(parent)
		if err != nil {
			return err
		}
		st, err := fdStat(f)
		f.Close()
		if err != nil {
			return err
		}
		if err = t19KeyParentMetadata(st); err != nil {
			return err
		}
		if parent == "/" {
			break
		}
	}
	var st unix.Stat_t
	if err := unix.Lstat(id.KeyFile, &st); err != nil {
		return err
	}
	return t19KeyMetadata(st, id.UID)
}

func t19KeyParentMetadata(st unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0755 {
		return errors.New("agent key parent chain must be root:root exactly 0755")
	}
	return nil
}
