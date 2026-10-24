//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// CheckMailSpoolAbsent proves the configured mailbox absent after useradd.
// MAIL_DIR takes precedence; MAIL_FILE is relative to the derived home.
// Even a missing mailbox refuses when its immediate parent is not protected.
func CheckMailSpoolAbsent(ctx context.Context, name, home string) (err error) {
	etc, e := OpenRoot("/etc")
	if e != nil {
		return e
	}
	defer closed(etc.f, &err)
	return checkMailSpoolAbsent(ctx, etc, name, home, ProtectedAbsent)
}

func mailSpoolPath(config []byte, name, home string) (string, error) {
	if !component(name) || !filepath.IsAbs(home) || filepath.Clean(home) != home || !utf8.Valid(config) || bytes.IndexByte(config, 0) >= 0 {
		return "", refusal("qualification_failed", "mail_config", nil)
	}
	settings := map[string]string{}
	for _, line := range strings.Split(string(config), "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 0 || (fields[0] != "MAIL_DIR" && fields[0] != "MAIL_FILE") {
			continue
		}
		if len(fields) != 2 || settings[fields[0]] != "" {
			return "", refusal("qualification_failed", "mail_config", nil)
		}
		settings[fields[0]] = fields[1]
	}
	if file := settings["MAIL_FILE"]; file != "" && !relative(file) {
		return "", refusal("qualification_failed", "mail_config", nil)
	}
	if dir := settings["MAIL_DIR"]; dir != "" {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			return "", refusal("qualification_failed", "mail_config", nil)
		}
		return filepath.Join(dir, name), nil
	}
	if file := settings["MAIL_FILE"]; file != "" {
		return filepath.Join(home, file), nil
	}
	return filepath.Join("/var/mail", name), nil
}

func checkMailSpoolAbsent(ctx context.Context, etc *Dir, name, home string, absent func(string) error) error {
	protection := func(s unix.Stat_t) bool { return s.Gid == etc.group && s.Mode&0022 == 0 }
	var before, after unix.Stat_t
	config, e := protectedReadChecked(ctx, etc, "login.defs", 1<<20, protection, &before)
	if e != nil {
		return e
	}
	path, e := mailSpoolPath(config, name, home)
	if e != nil {
		return e
	}
	if e = absent(path); e != nil {
		return refusal("backend_failed", "mail_spool_absence", e)
	}
	now, e := protectedReadChecked(ctx, etc, "login.defs", 1<<20, protection, &after)
	if e != nil {
		return e
	}
	if !bytes.Equal(config, now) || !stableStat(before, after) {
		return refusal("qualification_failed", "mail_config_changed", nil)
	}
	return ctx.Err()
}
