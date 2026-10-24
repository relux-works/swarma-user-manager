//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// MailSpoolPolicy is trusted host policy, never request data. StationRanges must
// include every configured UID and GID interval. Zero SystemBoundary means the
// current Linux profile's exclusive system-account boundary, 1000.
type MailSpoolPolicy struct {
	SystemBoundary uint32
	StationRanges  []IDInterval
	Limits         Limits
}

// CheckMailSpoolAbsent proves the configured mailbox absent after useradd.
// MAIL_DIR takes precedence; MAIL_FILE is relative to the derived home.
// Even a missing mailbox refuses without a qualified immediate parent.
func CheckMailSpoolAbsent(ctx context.Context, name, home string, policy MailSpoolPolicy) (err error) {
	c, cancel, e := budget(ctx, policy.Limits)
	if e != nil {
		return e
	}
	defer cancel()
	if e = policy.validate(); e != nil {
		return e
	}
	etc, e := OpenRoot("/etc")
	if e != nil {
		return e
	}
	defer closed(etc.f, &err)
	return checkMailSpoolAbsent(c, etc, name, home, func(path string) error {
		return qualifiedMailSpoolAbsent(c, etc, path, policy)
	})
}

func mailSpoolPath(config []byte, name, home string) (string, error) {
	if !component(name) || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", refusal("qualification_failed", "mail_config", nil)
	}
	settings := map[string]string{}
	for _, line := range strings.Split(string(config), "\n") {
		// shadow 4.17.4 lib/getdef.c:535,560 uses a 1024-byte fgets buffer.
		// Bound ALL physical lines so a continuation chunk cannot hide a key.
		if len(line) > 1022 {
			return "", refusal("qualification_failed", "mail_config", nil)
		}
		for i := 0; i < len(line); i++ {
			if line[i] != '\t' && (line[i] < ' ' || line[i] > '~') {
				return "", refusal("qualification_failed", "mail_config", nil)
			}
		}
		// Model only the ASCII whitespace/comment boundaries at :565-579.
		// Hash suffixes are NOT comments. Refuse quotes/trailing text rather
		// than guessing at the reference's quoted-value and literal handling.
		line = strings.Trim(line, " \t")
		if line == "" || line[0] == '#' {
			continue
		}
		separator := strings.IndexAny(line, " \t")
		key := line
		if separator >= 0 {
			key = line[:separator]
		}
		if key != "MAIL_DIR" && key != "MAIL_FILE" {
			continue
		}
		if separator < 0 {
			return "", refusal("qualification_failed", "mail_config", nil)
		}
		value := strings.TrimLeft(line[separator+1:], " \t")
		_, duplicate := settings[key]
		// The reference is last-definition-wins (:588,399-400); this
		// deliberately stricter subset refuses every duplicate instead.
		if value == "" || strings.ContainsAny(value, " \t#\"'") || duplicate {
			return "", refusal("qualification_failed", "mail_config", nil)
		}
		settings[key] = value
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
