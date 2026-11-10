//go:build linux

package slotd

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

func observeAccounts(ctx context.Context, id slotIdentity) (accountObservation, error) {
	if e := ctx.Err(); e != nil {
		return accountObservation{}, e
	}
	var databases [4][]byte
	for i, name := range []string{"passwd", "group", "shadow", "gshadow"} {
		b, e := readAccountDatabase("/etc/"+name, i >= 2)
		if e != nil {
			return accountObservation{}, e
		}
		databases[i] = b
	}
	o, e := observeAccountBytes(id, databases[0], databases[1], databases[2], databases[3])
	if e != nil {
		return o, e
	}
	return o, verifyNSS(id, o)
}
func readAccountDatabase(path string, secret bool) ([]byte, error) {
	parent, e := openTrustedDir(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	f, e := childFD(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := fdStat(f)
	if e != nil {
		return nil, e
	}
	if secret && st.Mode&0007 != 0 {
		return nil, errors.New("world-accessible account credentials")
	}
	return readProtectedFD(f, 0, 8*1024*1024)
}
func verifyNSS(id slotIdentity, o accountObservation) error {
	number := strconv.FormatUint(uint64(id.UID), 10)
	named, ne := user.Lookup(id.Name)
	numeric, ie := user.LookupId(number)
	if o.passwd == "" {
		var n user.UnknownUserError
		var i user.UnknownUserIdError
		if !errors.As(ne, &n) || !errors.As(ie, &i) {
			return errors.New("NSS account absence unproved")
		}
	} else {
		if ne != nil || ie != nil || named.Username != id.Name || numeric.Username != id.Name || named.Uid != number || numeric.Uid != number || named.Gid != number || numeric.Gid != number || named.HomeDir != id.Home || numeric.HomeDir != id.Home {
			return errors.New("NSS account mismatch")
		}
		gids, e := named.GroupIds()
		if e != nil {
			return e
		}
		if len(gids) != 1 {
			return errors.New("NSS primary group agreement unproved")
		}
		for _, gid := range gids {
			if gid != number {
				return errors.New("NSS supplementary group refused")
			}
		}
	}
	group, ge := user.LookupGroup(id.Name)
	byID, gide := user.LookupGroupId(number)
	if o.group == "" {
		var n user.UnknownGroupError
		var i user.UnknownGroupIdError
		if !errors.As(ge, &n) || !errors.As(gide, &i) {
			return errors.New("NSS group absence unproved")
		}
	} else if ge != nil || gide != nil || group.Name != id.Name || byID.Name != id.Name || group.Gid != number || byID.Gid != number {
		return errors.New("NSS group mismatch")
	}
	return nil
}
func createAccounts(ctx context.Context, id slotIdentity, homeRoot, slot string) (*accountReceipt, error) {
	o, e := observeAccounts(ctx, id)
	if e != nil {
		return nil, e
	}
	if !o.empty() {
		return nil, errors.New("unmanaged identity exists")
	}
	allocation, e := linuxos.Allocate(ctx, linuxos.Range{Min: id.UID, Max: id.UID}, linuxos.JournalView{}, linuxos.NSS{}, homeRoot, "slot-"+slot)
	if e != nil {
		return nil, e
	}
	if allocation.Name() != id.Name || allocation.Home() != id.Home || allocation.UID() != id.UID {
		return nil, errors.New("allocation binding mismatch")
	}
	commands, e := allocation.Commands()
	if e != nil {
		return nil, e
	}
	for _, command := range commands {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		e = linuxos.RunAccountTool(bounded, command)
		cancel()
		if e != nil {
			return nil, e
		}
	}
	o, e = observeAccounts(ctx, id)
	if e != nil {
		return nil, e
	}
	return o.receipt()
}

// Restart retirement is demo-local under amendment 1. It cannot manufacture a
// linuxos Allocation. Every deletion rechecks the original creation receipt.
func retireAccounts(ctx context.Context, r *durableRecord) error {
	o, e := observeAccounts(ctx, r.Identity)
	if e != nil {
		return e
	}
	if e = o.matches(r.Accounts); e != nil {
		return e
	}
	if o.passwd != "" {
		if e = runRetirementTool(ctx, "/usr/sbin/userdel", r.Identity.Name); e != nil {
			return e
		}
		o, e = observeAccounts(ctx, r.Identity)
		if e != nil {
			return e
		}
		if e = o.matches(r.Accounts); e != nil {
			return e
		}
		if o.passwd != "" || o.shadow {
			return errors.New("account removal unproved")
		}
	}
	if o.group != "" {
		if e = runRetirementTool(ctx, "/usr/sbin/groupdel", r.Identity.Name); e != nil {
			return e
		}
	}
	o, e = observeAccounts(ctx, r.Identity)
	if e != nil {
		return e
	}
	if !o.empty() {
		return errors.New("account absence unproved")
	}
	return nil
}
func runRetirementTool(ctx context.Context, path, name string) error {
	if path != "/usr/sbin/userdel" && path != "/usr/sbin/groupdel" {
		return errors.New("invalid retirement executable")
	}
	// The entire fixed executable and its ancestry are root protected and
	// non-writable to group/other; no caller can substitute an argv or shell.
	if _, e := readProtected(path, 0, 64*1024*1024); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--", name)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr boundedOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	e := cmd.Run()
	if stdout.truncated || stderr.truncated {
		e = errors.Join(e, errors.New("retirement output truncated"))
	}
	if e != nil {
		return &toolFailure{e, stdout.bytes, stderr.bytes}
	}
	return nil
}
