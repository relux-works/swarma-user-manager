//go:build linux

package slotd

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"golang.org/x/sys/unix"
)

type linuxEffects struct {
	policy   policy
	homes    *homeRoot
	accounts sync.Mutex
}

func (e *linuxEffects) prepareCreate(ctx context.Context, r *durableRecord, bootstrap []byte) error {
	proc, err := linuxos.OpenProc()
	if err != nil {
		return err
	}
	processes, err := proc.Processes(ctx, r.Identity.UID, 100000)
	closeErr := proc.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(processes) != 0 {
		return errors.New("unmanaged UID processes exist")
	}
	if err := e.homes.absent(r.Identity); err != nil {
		return err
	}
	e.accounts.Lock()
	defer e.accounts.Unlock()
	o, err := observeAccounts(ctx, r.Identity)
	if err != nil {
		return err
	}
	if !o.empty() {
		return errors.New("unmanaged identity exists")
	}
	v, err := unitProperties(ctx, r.Identity)
	if err != nil {
		return err
	}
	if v != nil {
		return errors.New("unmanaged unit exists")
	}
	if err = proveCgroupGone(r); err != nil {
		return err
	}
	exists, err := nftPresent(ctx, r.Identity)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("unmanaged nft table exists")
	}
	if e.policy.Version == 2 {
		return prepareStationCustody(e.policy, r, bootstrap)
	}
	return nil
}
func (e *linuxEffects) create(ctx context.Context, r *durableRecord, bootstrap []byte, persist func() error) error {
	e.accounts.Lock()
	defer e.accounts.Unlock()
	receipt, err := createAccounts(ctx, r.Identity, e.policy.HomeRoot, r.Slot)
	if err != nil {
		return err
	}
	r.Accounts = receipt
	r.Phase = ""
	if err = persist(); err != nil {
		return err
	}
	if err = e.homes.create(r, bootstrap, persist); err != nil {
		return err
	}
	if r.Station != nil {
		roots, e := openStationRoots()
		if e != nil {
			return e
		}
		err = materializeStation(roots, r, bootstrap, persist)
		roots.close()
		if err != nil {
			return err
		}
	}
	return installNFT(ctx, e.policy, r, persist)
}
func (e *linuxEffects) prepareStart(ctx context.Context, r *durableRecord) error {
	e.accounts.Lock()
	defer e.accounts.Unlock()
	o, err := observeAccounts(ctx, r.Identity)
	if err != nil {
		return err
	}
	actual, err := o.receipt()
	if err != nil {
		return err
	}
	if r.Accounts == nil || *actual != *r.Accounts {
		return errors.New("account creation receipt mismatch")
	}
	f, err := e.homes.openOwned(r)
	if err != nil {
		return err
	}
	f.Close()
	if err = verifyPayload(e.policy); err != nil {
		return err
	}
	if e.policy.Version == 2 {
		if r.Binding.State != running {
			if err = e.proveUIDQuiet(ctx, r); err != nil {
				return err
			}
		}
		roots, err := openStationRoots()
		if err != nil {
			return err
		}
		err = verifyStationInputs(roots, e.policy, r)
		roots.close()
		if err != nil {
			return err
		}
	}
	return verifyNFT(ctx, e.policy, r)
}
func (e *linuxEffects) start(ctx context.Context, r *durableRecord, persist func() error, now time.Time) error {
	return startUnit(ctx, e.policy, r, persist, now)
}
func (e *linuxEffects) verifyRunning(ctx context.Context, r *durableRecord) error {
	v, err := unitProperties(ctx, r.Identity)
	if err != nil {
		return err
	}
	if err = verifyUnitProperties(v, e.policy, r); err != nil {
		return err
	}
	if e.policy.Version == 2 {
		return verifyStationUnitExec(ctx, r)
	}
	return nil
}
func (e *linuxEffects) proveUIDQuiet(ctx context.Context, r *durableRecord) error {
	proc, err := linuxos.OpenProc()
	if err != nil {
		return err
	}
	processes, err := proc.Processes(ctx, r.Identity.UID, 100000)
	closeErr := proc.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(processes) != 0 {
		return errors.New("slot UID processes prevent custody transition")
	}
	return nil
}
func (e *linuxEffects) stopProcesses(ctx context.Context, r *durableRecord) error {
	proc, err := linuxos.OpenProc()
	if err != nil {
		return err
	}
	defer proc.Close()
	admitted, err := proc.Processes(ctx, r.Identity.UID, 100000)
	if err != nil {
		return err
	}
	_, err = proc.Stop(ctx, r.Identity.UID, admitted, linuxos.StopTiming{Grace: 3 * time.Second, Quiet: 300 * time.Millisecond, Poll: 20 * time.Millisecond, MaxProcesses: 100000})
	return err
}
func (e *linuxEffects) stop(ctx context.Context, r *durableRecord) error {
	e.accounts.Lock()
	defer e.accounts.Unlock()
	o, err := observeAccounts(ctx, r.Identity)
	if err != nil {
		return err
	}
	if err = o.matches(r.Accounts); err != nil {
		return err
	}
	if err = stopUnit(ctx, e.policy, r); err != nil {
		return err
	}
	return e.stopProcesses(ctx, r)
}
func (e *linuxEffects) prepareDestroy(ctx context.Context, r *durableRecord) error {
	// Actual active-unit refusal precedes every mutation, independent of the
	// stored state. Account/hash and filesystem preflight also precede deletion.
	if err := proveUnitInactive(ctx, r); err != nil {
		return err
	}
	e.accounts.Lock()
	defer e.accounts.Unlock()
	o, err := observeAccounts(ctx, r.Identity)
	if err != nil {
		return err
	}
	if r.Accounts == nil {
		if !o.empty() {
			return errors.New("ambiguous account creation")
		}
	} else if err = o.matches(r.Accounts); err != nil {
		return err
	}
	if r.Home == nil {
		if err = e.homes.absent(r.Identity); err != nil {
			return err
		}
	} else if err = e.homes.preflight(r); err != nil {
		return err
	}
	if e.policy.Version == 2 {
		if err = e.proveUIDQuiet(ctx, r); err != nil {
			return err
		}
		roots, err := openStationRoots()
		if err != nil {
			return err
		}
		_, err = stationDeletionPlan(roots, r)
		roots.close()
		if err != nil {
			return err
		}
	}
	exists, err := nftPresent(ctx, r.Identity)
	if err != nil {
		return err
	}
	if exists {
		return verifyNFT(ctx, e.policy, r)
	}
	return nil
}
func (e *linuxEffects) removeNFT(ctx context.Context, r *durableRecord) error {
	return removeNFT(ctx, e.policy, r)
}
func (e *linuxEffects) retire(ctx context.Context, r *durableRecord) error {
	e.accounts.Lock()
	defer e.accounts.Unlock()
	o, err := observeAccounts(ctx, r.Identity)
	if err != nil {
		return err
	}
	if r.Accounts == nil {
		if !o.empty() {
			return errors.New("ambiguous account creation")
		}
		return nil
	}
	if err = o.matches(r.Accounts); err != nil {
		return err
	}
	if err = e.stopProcesses(ctx, r); err != nil {
		return err
	}
	return retireAccounts(ctx, r)
}
func (e *linuxEffects) removeHome(ctx context.Context, r *durableRecord) error {
	if r.Station != nil {
		if err := e.proveUIDQuiet(ctx, r); err != nil {
			return err
		}
		// Repeat both tree preflights immediately before the first unlink.
		if r.Home != nil {
			if err := e.homes.preflight(r); err != nil {
				return err
			}
		} else if err := e.homes.absent(r.Identity); err != nil {
			return err
		}
		roots, err := openStationRoots()
		if err != nil {
			return err
		}
		defer roots.close()
		if _, err = stationDeletionPlan(roots, r); err != nil {
			return err
		}
		if err = removeStation(roots, r); err != nil {
			return err
		}
	}
	if r.Home == nil {
		return e.homes.absent(r.Identity)
	}
	return e.homes.remove(r)
}
func bootClock() (string, uint64, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, err
	}
	boot := string(b)
	if len(boot) != 37 || boot[36] != '\n' || !bootPattern.MatchString(boot[:36]) {
		return "", 0, errors.New("invalid kernel boot identity")
	}
	var ts unix.Timespec
	if err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return "", 0, err
	}
	if ts.Sec < 0 || uint64(ts.Sec) > (^uint64(0)-uint64(ts.Nsec))/1000000000 {
		return "", 0, errors.New("invalid kernel boot clock")
	}
	return boot[:36], uint64(ts.Sec)*1000000000 + uint64(ts.Nsec), nil
}
