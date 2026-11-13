//go:build linux

package slotd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const t19BootstrapPrefix = "t19-observational-"

type t19ExistingAdmission struct {
	policy    policy
	slot      string
	initial   response
	read      func() (durableRecord, error)
	preflight func(context.Context, durableRecord) error
}

func t19ExistingGate(p policy, slot string, initial response, read func() (durableRecord, error), preflight func(context.Context, durableRecord) error) *t19ExistingAdmission {
	return &t19ExistingAdmission{p, slot, initial, read, preflight}
}

func (a *t19ExistingAdmission) check(ctx context.Context, current response) error {
	if current != a.initial {
		return errors.New("pre-existing slot binding changed before create")
	}
	return t19AdmitExisting(ctx, a.policy, a.slot, current, a.read, a.preflight)
}

// Wire status alone has no identity. Decode the protected record against the
// unchanged policy, match the exact status binding, then rerun production's
// read-only adoption preflight. No record is edited or moved aside.
func t19AdmitExisting(ctx context.Context, p policy, slot string, old response, read func() (durableRecord, error), preflight func(context.Context, durableRecord) error) error {
	if old.Slot != slot {
		return errors.New("qualification status names another slot")
	}
	if old.State == absent {
		if _, err := read(); !errors.Is(err, os.ErrNotExist) {
			return errors.New("absent wire status lacks an absent protected record")
		}
		return nil
	}
	if old.State != destroyed {
		return errors.New("qualification reuse requires a destroyed tombstone")
	}
	id, err := p.identity(slot)
	if err != nil || p.Version != 0 || !id.adopted() {
		return errors.New("rewindow requires the same declared adopted v0 slot")
	}
	r, err := read()
	if err != nil {
		return fmt.Errorf("rewindow protected record: %w", err)
	}
	if r.Version != 1 || r.Slot != slot || r.Identity != id || r.Binding.State != destroyed || r.Phase != "" {
		return errors.New("rewindow tombstone identity/state differs from the declared slot/account/key")
	}
	if old.NotAfter != r.Binding.NotAfter.Format(time.RFC3339) || old.PayloadSHA256 != r.Binding.PayloadSHA256 || old.BootstrapSHA256 != r.Binding.BootstrapSHA256 {
		return errors.New("rewindow wire and protected record bindings differ")
	}
	if preflight == nil {
		return errors.New("rewindow has no independent residue preflight")
	}
	if err = preflight(ctx, r); err != nil {
		return fmt.Errorf("rewindow residue/adoption preflight: %w", err)
	}
	return nil
}

func t19RewindowPreflight(ctx context.Context, p policy, r durableRecord) error {
	if p.Version != 0 || !r.Identity.adopted() {
		return errors.New("rewindow preflight requires adopted v0 identity")
	}
	homes, err := openHomeRoot(p)
	if err != nil {
		return err
	}
	defer homes.close()
	// v0 prepareCreate only inspects: UID processes, absent home, whole-view
	// adoptedNoResidue, key ancestry, accounts/NSS, absent unit/cgroup/NFT.
	effects := linuxEffects{policy: p, homes: homes}
	if err = effects.prepareCreate(ctx, &r, nil); err != nil {
		return err
	}
	if r.Accounts != nil {
		o, err := observeAccounts(ctx, r.Identity)
		if err != nil {
			return err
		}
		if err = o.matches(r.Accounts); err != nil {
			return err
		}
	}
	return t19VerifyKey(r.Identity)
}

func t19RunIDValid(id string) bool {
	return len(id) == 64 && tokenPattern.MatchString(id) && id != strings.Repeat("0", 64)
}

// The random create bootstrap is a public attempt nonce, never an agent key.
// Both observer and driver derive paths/marker from these very same bytes.
func t19SpecForRun(base t19Spec, id string) (t19Spec, error) {
	if !t19RunIDValid(id) {
		return base, errors.New("invalid fresh T19 run identity")
	}
	base.Report = filepath.Join(filepath.Dir(base.Report), "t19-realhost-"+id+".json")
	base.JournalLine += "-" + id
	return base, nil
}

func t19ReadRunID(base t19Spec, uid uint32) (string, error) {
	fd, err := unix.Open(filepath.Join(filepath.Dir(base.Report), "bootstrap"), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "T19 attempt bootstrap")
	defer f.Close()
	st, err := fdStat(f)
	if err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uid || st.Gid != uid || st.Nlink != 1 {
		return "", errors.New("T19 attempt bootstrap metadata refused")
	}
	b, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil {
		return "", err
	}
	id, ok := strings.CutPrefix(string(b), t19BootstrapPrefix)
	if !ok || !t19RunIDValid(id) {
		return "", errors.New("T19 attempt bootstrap is not a fresh run identity")
	}
	return id, nil
}

func t19RequireRunID(spec t19Spec, uid uint32, expected string) error {
	id, err := t19ReadRunID(spec, uid)
	if err != nil || !t19RunIDValid(expected) || id != expected {
		return errors.New("created bootstrap differs from this run identity")
	}
	return nil
}

func t19RunArtifactsAbsent(spec t19Spec) error {
	for _, name := range []string{spec.Report, spec.Report + ".partial", spec.Report + ".peer"} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("current-run artifact already exists or cannot be inspected: " + name)
		}
	}
	return nil
}

func t19JournalArgs(unit, line, invocation string) ([]string, error) {
	if len(invocation) != 32 || !tokenPattern.MatchString(invocation) || invocation == strings.Repeat("0", 32) {
		return nil, errors.New("journal requires the current systemd invocation identity")
	}
	return []string{"--no-pager", "-o", "cat", "_SYSTEMD_UNIT=" + unit, "_SYSTEMD_INVOCATION_ID=" + invocation, "--grep", line}, nil
}
