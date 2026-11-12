package slotd

import (
	"errors"
	"strconv"
	"strings"
)

type accountObservation struct {
	passwd, group string
	shadow        bool
}

// Database lines never enter public errors or durable state. Only the hashes of
// the exact passwd/group lines, including their LF, become creation receipts.
func observeAccountBytes(id slotIdentity, passwd, group, shadow, gshadow []byte) (accountObservation, error) {
	var out accountObservation
	parse := func(b []byte, fields int, visit func([]string, string) error) error {
		if len(b) > 8*1024*1024 || len(b) == 0 || b[len(b)-1] != '\n' {
			return errors.New("invalid account database")
		}
		names := map[string]bool{}
		for _, line := range strings.Split(string(b[:len(b)-1]), "\n") {
			f := strings.Split(line, ":")
			if len(line) > 16384 || len(f) != fields || f[0] == "" || names[f[0]] {
				return errors.New("ambiguous account database")
			}
			names[f[0]] = true
			if e := visit(f, line+"\n"); e != nil {
				return e
			}
		}
		return nil
	}
	number := strconv.FormatUint(uint64(id.UID), 10)
	socketNumber := strconv.FormatUint(uint64(id.SocketGID), 10)
	socketSeen := false
	canonicalID := func(s string) bool {
		n, e := strconv.ParseUint(s, 10, 32)
		return e == nil && strconv.FormatUint(n, 10) == s
	}
	if e := parse(passwd, 7, func(f []string, line string) error {
		if !canonicalID(f[2]) || !canonicalID(f[3]) {
			return errors.New("noncanonical account ID")
		}
		if f[0] != id.Name {
			if f[2] == number || f[3] == number {
				return errors.New("UID or primary group collision")
			}
			return nil
		}
		// f[3] == f[2] is the GID == UID own-group rule, also for the
		// adopted account (adoption condition 9).
		if f[1] != "x" || f[2] != number || f[3] != number || f[5] != id.passwdHome() || f[6] != "/usr/sbin/nologin" {
			return errors.New("account identity mismatch")
		}
		out.passwd = line
		return nil
	}); e != nil {
		return out, e
	}
	if e := parse(group, 4, func(f []string, line string) error {
		if !canonicalID(f[2]) {
			return errors.New("noncanonical group ID")
		}
		if f[0] == id.Name {
			if f[2] != number || f[3] != "" {
				return errors.New("group identity mismatch")
			}
			out.group = line
			return nil
		}
		if f[2] == number {
			return errors.New("GID collision")
		}
		member := false
		for _, m := range strings.Split(f[3], ",") {
			member = member || m == id.Name
		}
		// The adopted account's one declared socket group: exact name, exact
		// GID, and the account listed as a member. Any other group naming
		// the account is refused exactly as for a worker account.
		if id.adopted() && (f[0] == id.SocketGroup || f[2] == socketNumber) {
			if f[0] != id.SocketGroup || f[2] != socketNumber {
				return errors.New("socket group identity mismatch")
			}
			if !member {
				return errors.New("socket group membership missing")
			}
			socketSeen = true
			return nil
		}
		if member {
			return errors.New("supplementary group refused")
		}
		return nil
	}); e != nil {
		return out, e
	}
	if id.adopted() && !socketSeen {
		return out, errors.New("declared socket group missing")
	}
	if e := parse(shadow, 9, func(f []string, _ string) error {
		if f[0] != id.Name {
			return nil
		}
		if !strings.HasPrefix(f[1], "!") && !strings.HasPrefix(f[1], "*") {
			return errors.New("unlocked account refused")
		}
		out.shadow = true
		return nil
	}); e != nil {
		return out, e
	}
	gs := false
	if e := parse(gshadow, 4, func(f []string, _ string) error {
		if f[0] != id.Name {
			return nil
		}
		// "!*" is systemd-sysusers' locked-and-invalid marker (adopted account).
		if (f[1] != "!" && f[1] != "*" && f[1] != "!!" && f[1] != "!*") || f[2] != "" || f[3] != "" {
			return errors.New("group credentials refused")
		}
		gs = true
		return nil
	}); e != nil {
		return out, e
	}
	if (out.passwd != "") != out.shadow || (out.group != "") != gs {
		return out, errors.New("account databases disagree")
	}
	return out, nil
}
func (o accountObservation) empty() bool { return o.passwd == "" && o.group == "" && !o.shadow }
func (o accountObservation) receipt() (*accountReceipt, error) {
	if o.passwd == "" || o.group == "" || !o.shadow {
		return nil, errors.New("incomplete creation observation")
	}
	return &accountReceipt{digest([]byte(o.passwd)), digest([]byte(o.group)), true}, nil
}
func (o accountObservation) matches(receipt *accountReceipt) error {
	if receipt == nil {
		return errors.New("creation receipt missing")
	}
	if o.passwd != "" && (digest([]byte(o.passwd)) != receipt.PasswdSHA256 || !o.shadow) {
		return errors.New("account receipt mismatch")
	}
	if o.group != "" && digest([]byte(o.group)) != receipt.GroupSHA256 {
		return errors.New("group receipt mismatch")
	}
	return nil
}

// admitGroupSet is the NSS group rule (adoption condition 2): a worker account
// resolves to exactly {own GID == UID}; the adopted account to exactly
// {own GID == UID, declared socket GID}. Nothing else, no duplicates.
func admitGroupSet(id slotIdentity, gids []string) error {
	want := map[string]bool{strconv.FormatUint(uint64(id.UID), 10): true}
	if id.adopted() {
		want[strconv.FormatUint(uint64(id.SocketGID), 10)] = true
	}
	if len(gids) != len(want) {
		return errors.New("NSS primary group agreement unproved")
	}
	seen := map[string]bool{}
	for _, gid := range gids {
		if !want[gid] || seen[gid] {
			return errors.New("NSS supplementary group refused")
		}
		seen[gid] = true
	}
	return nil
}
