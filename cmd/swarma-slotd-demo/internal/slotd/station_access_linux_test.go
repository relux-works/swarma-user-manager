//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type stationAccessProbe struct {
	UID                                                                    uint32
	OwnBootstrap, OtherBootstrap, OwnJournal, OtherJournal, ExpectedSHA256 string
}
type stationAccessReport struct {
	Identity, GroupsEmpty, OwnRead, OwnWriteDenied, OtherReadDenied, OwnJournal, OtherJournalDenied bool
}

// This non-root-only fixture subprocess exposes boolean observations, never
// bootstrap bytes. The parent supplies only its owned disposable fixture paths.
func runStationAccessProbe(args []string) int {
	if os.Geteuid() == 0 || len(args) != 1 {
		return 91
	}
	var p stationAccessProbe
	if json.Unmarshal([]byte(args[0]), &p) != nil {
		return 92
	}
	r := stationAccessReport{Identity: uint32(os.Geteuid()) == p.UID && uint32(os.Getegid()) == p.UID}
	groups, err := os.Getgroups()
	r.GroupsEmpty = err == nil && len(groups) == 0
	f, err := os.Open(p.OwnBootstrap)
	if err == nil {
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		r.OwnRead = e == nil && len(b) <= 4096 && digest(b) == p.ExpectedSHA256
	}
	f, err = os.OpenFile(p.OwnBootstrap, os.O_WRONLY, 0)
	if f != nil {
		f.Close()
	}
	r.OwnWriteDenied = errors.Is(err, unix.EACCES)
	f, err = os.Open(p.OtherBootstrap)
	if f != nil {
		f.Close()
	}
	r.OtherReadDenied = errors.Is(err, unix.EACCES)
	name := ".journal-" + strconv.FormatUint(uint64(p.UID), 10)
	own := filepath.Join(p.OwnJournal, name)
	f, err = os.OpenFile(own, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, writeErr := f.Write([]byte("inert access witness"))
		closeErr := f.Close()
		removeErr := os.Remove(own)
		r.OwnJournal = writeErr == nil && closeErr == nil && removeErr == nil
	}
	other := filepath.Join(p.OtherJournal, name)
	f, err = os.OpenFile(other, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if f != nil {
		f.Close()
		_ = os.Remove(other)
	}
	r.OtherJournalDenied = errors.Is(err, unix.EACCES)
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 93
	}
	return 0
}

// Proves kernel DAC in both directions with two real U:GID credential sets and
// empty supplementary groups: each reads its own immutable bootstrap, writes
// only its own journal, and cannot read/write the other slot. No NSS account,
// signed-input, systemd namespace or payload consumer qualification is claimed.
func TestRootStationCrossUIDAccess(t *testing.T) {
	requireHostedRoot(t)
	p, template := stationRecordFixture(t)
	roots := fixtureCustodyRoots(t)
	makeSlot := func(bootstrap []byte) durableRecord {
		r := *copyRecord(&template)
		r.Slot = strconv.FormatUint(uint64(7000+fixtureSlot.Add(1)), 10)
		var err error
		r.Identity, err = p.identity(r.Slot)
		if err != nil {
			t.Fatal(err)
		}
		r.Binding.BootstrapSHA256 = digest(bootstrap)
		r.Station.Generation = fmt.Sprintf("%032x", r.Identity.UID)
		r.Station.BookingID = fmt.Sprintf("%064x", r.Identity.UID)
		r.Station.Manifest = nil
		r.Station.ManifestSHA256 = ""
		r.Station.Objects = nil
		r.Station.staged = signedStationSnapshot(t, *p.Payload.StationProfile, r.Identity.UID)
		if err = materializeStation(roots, &r, bootstrap, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		return r
	}
	first, second := makeSlot([]byte("first inert bootstrap")), makeSlot([]byte("second inert bootstrap"))
	base, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", roots.envelopes.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := fixturePayload(t, filepath.Dir(base))
	for _, pair := range [][2]durableRecord{{first, second}, {second, first}} {
		own, other := pair[0], pair[1]
		spec := stationAccessProbe{UID: own.Identity.UID, OwnBootstrap: filepath.Join(base, stationRelative(own.Identity.UID, stationSpecFor("bootstrap"))), OtherBootstrap: filepath.Join(base, stationRelative(other.Identity.UID, stationSpecFor("bootstrap"))), OwnJournal: filepath.Join(base, stationRelative(own.Identity.UID, stationSpecFor("journal"))), OtherJournal: filepath.Join(base, stationRelative(other.Identity.UID, stationSpecFor("journal"))), ExpectedSHA256: own.Binding.BootstrapSHA256}
		arg, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		cmd := exec.CommandContext(ctx, binaryPath, "slotd-station-access-probe", string(arg))
		cmd.Dir = filepath.Dir(base)
		cmd.Env = []string{}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: own.Identity.UID, Gid: own.Identity.UID, Groups: []uint32{}, NoSetGroups: false}}
		var output bytes.Buffer
		cmd.Stdout = &output
		if err = cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Logf("owned non-root station access probe PID %d", cmd.Process.Pid)
		err = cmd.Wait()
		cancel()
		if err != nil {
			t.Fatal("access probe", err)
		}
		var got stationAccessReport
		if output.Len() > 4096 || json.Unmarshal(output.Bytes(), &got) != nil {
			t.Fatal("invalid access report")
		}
		if got != (stationAccessReport{true, true, true, true, true, true, true}) {
			t.Fatal("cross-UID permission contract", got)
		}
	}
	for _, r := range []durableRecord{first, second} {
		v, err := openStationView(roots, &r)
		if err != nil {
			t.Fatal("access probe changed custody", err)
		}
		b, err := v.read("bootstrap", 4096)
		v.close()
		if err != nil || digest(b) != r.Binding.BootstrapSHA256 {
			t.Fatal("access probe changed input", err)
		}
	}
}
