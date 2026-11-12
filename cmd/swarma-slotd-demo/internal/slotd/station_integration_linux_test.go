//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"golang.org/x/sys/unix"
)

const stationViewReport = "station-main-view.json"

// This inert fixture consumes the exact typed argv and reports actual kernel
// view observations. It never contacts a gateway or claims payload/DA1 behavior.
func runStationMainViewProbe(argv []string) int {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Geteuid() {
		return 90
	}
	paths, err := payloadlaunch.PathsFor(uint32(os.Geteuid()))
	if err != nil {
		return 91
	}
	anchor, err := os.ReadFile(paths.Anchor)
	if err != nil {
		return 91
	}
	raw, err := os.ReadFile(paths.Manifest)
	if err != nil {
		return 91
	}
	m, err := payloadlaunch.ValidateSet(payloadlaunch.File{Present: true, Bytes: anchor}, payloadlaunch.File{Present: true, Bytes: raw}, uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		return 91
	}
	expected, err := payloadlaunch.Argv(m)
	if err != nil || !slices.Equal(argv, expected) {
		return 92
	}
	groups, err := os.Getgroups()
	identity := err == nil
	for _, gid := range groups {
		identity = identity && gid == os.Getegid()
	}
	readOnly := func(path string) bool {
		var st unix.Statfs_t
		return unix.Statfs(path, &st) == nil && st.Flags&unix.ST_RDONLY != 0
	}
	bootstrap, err := os.ReadFile(paths.Bootstrap)
	bootstrapOK := err == nil && digest(bootstrap) == m.Bootstrap.SHA256
	var journal unix.Stat_t
	journalOK := unix.Stat(paths.Journal, &journal) == nil && uint64(journal.Dev) == m.Journal.Directory.Device && journal.Ino == m.Journal.Directory.Inode
	// Retain this one inert owned turn across stop/start. Never overwrite an
	// existing mismatched file; the actual DA1 consumer is qualified separately.
	turn := filepath.Join(paths.Journal, "turn-"+strings.Repeat("a", 64)+".json")
	witness := []byte("inert retained infrastructure witness")
	f, createErr := os.OpenFile(turn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if createErr == nil {
		_, writeErr := f.Write(witness)
		modeErr, syncErr, closeErr := f.Chmod(0600), f.Sync(), f.Close()
		journalOK = journalOK && writeErr == nil && modeErr == nil && syncErr == nil && closeErr == nil
	} else {
		b, readErr := os.ReadFile(turn)
		journalOK = journalOK && errors.Is(createErr, os.ErrExist) && readErr == nil && bytes.Equal(b, witness)
	}
	work, err := os.Getwd()
	if err != nil {
		return 93
	}
	homeReadOnly, journalReadOnly := readOnly(work), readOnly(paths.Journal)
	result := []bool{identity, slices.Equal(argv, expected), readOnly(paths.Inputs), readOnly(filepath.Dir(paths.StaticManifest)), readOnly(filepath.Dir(paths.Anchor)), !homeReadOnly && !journalReadOnly, bootstrapOK, journalOK}
	b, err := json.Marshal(result)
	if err != nil || os.WriteFile(filepath.Join(work, stationViewReport), b, 0600) != nil {
		return 93
	}
	for {
		time.Sleep(time.Hour)
	}
}

func stationFixtureParents(t *testing.T) {
	t.Helper()
	requireHostedRoot(t)
	for _, parent := range []string{"/etc/swarma", payloadlaunch.EnvelopeRoot, payloadlaunch.AnchorRoot, stationStagingRoot} {
		if _, err := os.Lstat(parent); err == nil {
			if parent != "/etc/swarma" {
				t.Fatal("fixed station fixture parent must initially be absent", parent)
			}
			f, err := openTrustedDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		mode := os.FileMode(0755)
		if parent == stationStagingRoot {
			mode = 0700
		}
		if err := os.Mkdir(parent, mode); err != nil {
			t.Fatal(err)
		}
		// Remove only this empty directory; unexplained per-slot remnants fail
		// cleanup rather than granting permission to erase an unreceipted tree.
		t.Cleanup(func() {
			if err := os.Remove(parent); err != nil {
				t.Error(err)
			}
		})
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func stationFixtureStaging(t *testing.T, p policy, uid uint32) {
	t.Helper()
	dir := filepath.Join(stationStagingRoot, strconv.FormatUint(uint64(uid), 10))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s := signedStationSnapshotContents(t, *p.Payload.StationProfile, uid, []byte("inert public CA fixture"), stationModelFixture(t, *p.Payload.StationProfile))
	for name, b := range map[string][]byte{"10-install.conf": s.Anchor, "manifest.json": s.Manifest, "manifest.sig": s.Signature, "ca.pem": s.CA, "model.json": s.Model} {
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		})
		_, writeErr := f.Write(b)
		if err = errors.Join(writeErr, f.Chmod(0600), f.Sync(), f.Close()); err != nil {
			t.Fatal(err)
		}
	}
}

func realStationEngine(t *testing.T, r *durableRecord) (*lifecycle, *recordStore, policy, string) {
	t.Helper()
	p, initial, dir := rootFixture(t)
	*r = initial
	stationFixtureParents(t)
	fixtureFenceBinary(t)
	executable := fixturePayload(t, dir)
	b, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	typed, _ := stationRecordFixture(t)
	profile := *typed.Payload.StationProfile
	profile.Executable, profile.ExecutableSHA256 = executable, digest(b)
	profile.Model = "-fixture-model"
	p.Version, p.Payload, p.Egress = 2, payloadPolicy{StationProfile: &profile}, append([]egressRule{}, typed.Egress...)
	p.Caps = capsPolicy{CPUQuota: "100%", MemoryMax: "256M", TasksMax: 64}
	if err = p.validate(); err != nil {
		t.Fatal(err)
	}
	stationFixtureStaging(t, p, r.Identity.UID)
	engine, store, _ := realEngine(t, p, r, dir)
	return engine, store, p, dir
}

func createStationFixture(t *testing.T, engine *lifecycle, r *durableRecord) {
	t.Helper()
	q := currentCreate(t, r)
	q.Bootstrap = stationBootstrapFixture()
	q.BootstrapSHA256 = digest(q.Bootstrap)
	created, code := engine.apply(context.Background(), q)
	if created != nil {
		*r = *created
	}
	if code != "" {
		t.Fatal("typed create", code)
	}
}

func assertCurrentInputFenceResult(t *testing.T, r *durableRecord) {
	t.Helper()
	b, err := readProtected(filepath.Join(fenceRootPath, r.Slot+".result"), 0, 1024)
	var result fenceResult
	if err != nil || json.Unmarshal(b, &result) != nil || result.Token != r.UnitToken || result.Code != string(errFenceInput) {
		t.Fatal("specific current-token fence result missing", err)
	}
}

// A correctly signed public set can still select the wrong model. Exercise
// actual protected staging and then the lifecycle's no-effect boundary.
func assertStagedModelRefusal(t *testing.T, engine *lifecycle, p policy, r *durableRecord) {
	t.Helper()
	profile := *p.Payload.StationProfile
	model := stationModelFixture(t, profile)
	badModel := bytes.ReplaceAll(model, []byte(`"`+profile.Model+`"`), []byte(`"absent-selection"`))
	if bytes.Equal(model, badModel) {
		t.Fatal("signed model mismatch plant not applied")
	}
	write := func(model []byte) {
		s := signedStationSnapshotContents(t, profile, r.Identity.UID, []byte("inert public CA fixture"), model)
		for name, b := range map[string][]byte{"10-install.conf": s.Anchor, "manifest.json": s.Manifest, "manifest.sig": s.Signature, "ca.pem": s.CA, "model.json": s.Model} {
			path := filepath.Join(stationStagingRoot, strconv.FormatUint(uint64(r.Identity.UID), 10), name)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.Write(b)
			if err = errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(badModel)
	q := currentCreate(t, r)
	q.Bootstrap, q.BootstrapSHA256 = stationBootstrapFixture(), digest(stationBootstrapFixture())
	candidate := *copyRecord(r)
	candidate.Binding.BootstrapSHA256 = q.BootstrapSHA256
	candidate.Station = &stationRecord{BookingID: strings.Repeat("b", 64)}
	if _, err := readStationSnapshot(p, &candidate, q.Bootstrap); err == nil || err.Error() != "PAYLOAD_CONFIG" {
		t.Fatal("wrong signed-model staging refusal", err)
	}
	if next, code := engine.apply(context.Background(), q); code != internalError || next != nil {
		t.Fatal("signed model mismatch reached create", code)
	}
	if stored, err := engine.store.load(r.Slot); err != nil || stored != nil {
		t.Fatal("signed model mismatch wrote root state", err)
	}
	if o, err := observeAccounts(context.Background(), r.Identity); err != nil || !o.empty() {
		t.Fatal("signed model mismatch created account", err)
	}
	paths, err := payloadlaunch.PathsFor(r.Identity.UID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{r.Identity.Home, paths.Envelope, filepath.Dir(paths.Anchor)} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("signed model mismatch created runtime tree", err)
		}
	}
	if exists, err := nftPresent(context.Background(), r.Identity); err != nil || exists {
		t.Fatal("signed model mismatch created NFT", err)
	}
	write(model)
}

// Proves real account/NFT/custody creation, store reopen and typed unit launch
// retain generation, immutable bytes, directory/file receipts and an inert turn
// across stop/start. The child checks its actual main view and literal argv;
// this is infrastructure evidence, not real payload TLS/model/DA1 qualification.
func TestRootStationLifecycleRetention(t *testing.T) {
	requireHostedRoot(t)
	var r durableRecord
	engine, store, p, dir := realStationEngine(t, &r)
	assertStagedModelRefusal(t, engine, p, &r)
	createStationFixture(t, engine, &r)
	if _, err := os.Lstat(filepath.Join(r.Identity.Home, "bootstrap")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("typed create wrote home bootstrap")
	}
	before := copyRecord(&r)
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	var err error
	store, err = openStoreAt(p, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	engine.store = store
	var retainedTurn []byte
	var retainedInode uint64
	for cycle := 0; cycle < 2; cycle++ {
		next, code := engine.apply(context.Background(), request{Op: "start", Slot: r.Slot})
		if next != nil {
			r = *next
		}
		if code != "" {
			t.Fatal("typed start", code)
		}
		checkProbe(t, awaitProbe(t, filepath.Join(r.Identity.Home, stationViewReport), 8), []bool{true, true, true, true, true, true, true, true})
		pidBytes, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "show", "--property=MainPID", "--value", "--", r.Identity.Unit}})
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
		if err != nil || pid <= 0 {
			t.Fatal("owned station probe PID missing", err)
		}
		t.Logf("owned station probe PID %d in %s", pid, r.Identity.Unit)
		if !reflect.DeepEqual(r.Station, before.Station) {
			t.Fatal("start changed creation receipt")
		}
		paths, err := payloadlaunch.PathsFor(r.Identity.UID)
		if err != nil {
			t.Fatal(err)
		}
		turn := filepath.Join(paths.Journal, "turn-"+strings.Repeat("a", 64)+".json")
		b, err := os.ReadFile(turn)
		if err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err = unix.Stat(turn, &st); err != nil {
			t.Fatal(err)
		}
		if cycle == 0 {
			retainedTurn, retainedInode = b, st.Ino
		} else if !bytes.Equal(b, retainedTurn) || st.Ino != retainedInode {
			t.Fatal("retained turn replaced or changed")
		}
		if err = verifyStationUnitExec(context.Background(), &r); err != nil {
			t.Fatal("actual structured ExecStart", err)
		}
		next, code = engine.apply(context.Background(), request{Op: "stop", Slot: r.Slot})
		if next != nil {
			r = *next
		}
		if code != "" || !reflect.DeepEqual(r.Station, before.Station) {
			t.Fatal("stop changed retained receipt", code)
		}
		if err = os.Remove(filepath.Join(r.Identity.Home, stationViewReport)); err != nil {
			t.Fatal(err)
		}
	}
	retired, code := engine.apply(context.Background(), request{Op: "destroy", Slot: r.Slot})
	if retired != nil {
		r = *retired
	}
	if code != "" || r.Binding.State != destroyed {
		t.Fatal("typed retirement", code)
	}
	roots, err := openStationRoots()
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	if err = absentStation(roots, r.Identity.UID); err != nil {
		t.Fatal("retired custody remains", err)
	}
}

// Proves an actual pre-exec input mutation (after prepareStart passed) reaches
// fence_input with no main sentinel/turn, beside the valid sibling above. The
// plant first validates all current inputs; setup failure cannot count as refusal.
// Custody refuses the emptied input; its exact bytes restored, the set re-admits.
func TestRootStationPreexecRefusal(t *testing.T) {
	requireHostedRoot(t)
	var r durableRecord
	engine, store, p, _ := realStationEngine(t, &r)
	createStationFixture(t, engine, &r)
	roots, err := openStationRoots()
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	before, err := openStationView(roots, &r)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := map[string][]byte{}
	for _, spec := range stationSpecs {
		if !spec.directory && spec.name != "bootstrap" {
			unchanged[spec.name], err = before.read(spec.name, spec.max)
			if err != nil {
				before.close()
				t.Fatal(err)
			}
		}
	}
	before.close()
	root, err := openFenceRoot()
	if err != nil {
		t.Fatal(err)
	}
	plan := fencePlant{"station_bootstrap", os.Getenv("GITHUB_ACTIONS"), os.Getenv("RUNNER_ENVIRONMENT"), os.Getenv("SLOTD_ROOT_TESTS")}
	b, err := json.Marshal(plan)
	if err == nil {
		err = atomicPrivate(root, "plant-"+r.Slot+".json", append(b, '\n'))
	}
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(filepath.Join(fenceRootPath, "plant-"+r.Slot+".json")); err != nil {
			t.Error(err)
		}
	})
	var cause error
	engine.diagnostic = func(_ string, err error) { cause = err }
	next, code := engine.apply(context.Background(), request{Op: "start", Slot: r.Slot})
	if next != nil {
		r = *next
	}
	if code != internalError || !errors.Is(cause, errFenceInput) || r.Binding.State != failed {
		t.Fatal("wrong planted pre-exec refusal", code, cause)
	}
	assertCurrentInputFenceResult(t, &r)
	paths, err := payloadlaunch.PathsFor(r.Identity.UID)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{filepath.Join(r.Identity.Home, stationViewReport), filepath.Join(paths.Journal, "turn-"+strings.Repeat("a", 64)+".json")} {
		if _, err = os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused pre-exec ran main", err)
		}
	}
	// Independently prove that the intended plant actually changed its target.
	if st, err := os.Stat(paths.Bootstrap); err != nil || st.Size() != 0 {
		t.Fatal("bootstrap plant not applied", err)
	}
	// Custody metadata refuses the emptied input itself. Restore the exact
	// fixture bytes in place (same inode), then the complete view and input
	// admission must pass again: the refusal changed nothing but the plant.
	if v, err := openStationView(roots, &r); err == nil {
		v.close()
		t.Fatal("emptied bootstrap admitted by custody view")
	}
	f, err := os.OpenFile(paths.Bootstrap, os.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(stationBootstrapFixture()); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal("restore planted bootstrap", err)
	}
	if err = verifyStationInputs(roots, p, &r); err != nil {
		t.Fatal("input refusal changed custody", err)
	}
	after, err := openStationView(roots, &r)
	if err != nil {
		t.Fatal("input refusal changed custody", err)
	}
	defer after.close()
	for name, want := range unchanged {
		b, err := after.read(name, stationSpecFor(name).max)
		if err != nil || !bytes.Equal(b, want) {
			t.Fatal("input refusal changed unplanted input/journal state", name, err)
		}
	}
	if names, err := freshNames(after.files["journal"], 3); err != nil || !slices.Equal(names, []string{"binding.json", "delivery.lock"}) {
		t.Fatal("input refusal wrote journal entries", err)
	}
	stored, err := store.load(r.Slot)
	if err != nil || stored == nil || stored.Binding.State != failed {
		t.Fatal("pre-exec refusal not durable", err)
	}
	if err = verifyNFT(context.Background(), p, &r); err != nil {
		t.Fatal("input refusal changed NFT", err)
	}
	observed, err := observeAccounts(context.Background(), r.Identity)
	if err != nil || observed.matches(r.Accounts) != nil {
		t.Fatal("input refusal changed accounts", err)
	}
}

// Proves a real transient unit with a third writable bind fails the production
// prestart property check before main, beside the two-bind valid sibling. The
// fixture alters only its own generated invocation; no production seam exists.
func TestRootStationExtraWritableBind(t *testing.T) {
	requireHostedRoot(t)
	var r durableRecord
	engine, store, p, _ := realStationEngine(t, &r)
	createStationFixture(t, engine, &r)
	ctx := context.Background()
	if err := engine.effects.prepareStart(ctx, &r); err != nil {
		t.Fatal("valid baseline", err)
	}
	var err error
	r.UnitToken, err = randomToken()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.UnitRuntimeUS = r.Binding.NotAfter.Sub(now).Microseconds()
	r.Cgroup, r.Phase = "/system.slice/"+r.Identity.Unit, "unit-start"
	if err = store.save(&r); err != nil {
		t.Fatal(err)
	}
	fenceRoot, err := writeFenceRequest(p, &r)
	if err != nil {
		t.Fatal(err)
	}
	defer fenceRoot.Close()
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := startInvocation(p, r.Slot, r.Binding, now, m)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := payloadlaunch.PathsFor(r.Identity.UID)
	if err != nil {
		t.Fatal(err)
	}
	planted := 0
	for i, arg := range inv.Args {
		if strings.HasPrefix(arg, "--property=BindPaths=") {
			inv.Args[i] += " " + quoteSystemdWord(paths.Envelope)
			planted++
		}
	}
	if planted != 1 {
		t.Fatal("extra bind plant not applied exactly once")
	}
	prestart := "+" + fenceBinaryPath + " --enforcement-fence " + r.Slot + " " + r.UnitToken
	inv.Args = append([]string{"--property=Description=" + unitMarker(&r), "--property=Slice=system.slice", "--property=IPAccounting=no", "--property=Delegate=no", "--property=ExecStartPre=" + prestart, "--collect"}, inv.Args...)
	if _, err = runFixedTool(ctx, inv); err == nil {
		t.Fatal("unit with a third writable bind started")
	}
	if err = readFenceResult(fenceRoot, &r); !errors.Is(err, errFenceInput) {
		t.Fatal("wrong extra-bind fence refusal", err)
	}
	assertCurrentInputFenceResult(t, &r)
	if _, err = os.Lstat(filepath.Join(r.Identity.Home, stationViewReport)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("extra-bind unit executed main", err)
	}
	if engine.failure(&r, errFenceInput) != internalError {
		t.Fatal("extra-bind failure not recorded")
	}
	// The rejected unit must leave the valid current signed/custody input set.
	roots, err := openStationRoots()
	if err != nil {
		t.Fatal(err)
	}
	defer roots.close()
	if err = verifyStationInputs(roots, p, &r); err != nil {
		t.Fatal("extra-bind refusal changed inputs", err)
	}
	view, err := openStationView(roots, &r)
	if err != nil {
		t.Fatal(err)
	}
	defer view.close()
	if names, err := freshNames(view.files["journal"], 3); err != nil || !slices.Equal(names, []string{"binding.json", "delivery.lock"}) {
		t.Fatal("extra-bind refusal wrote journal entries", err)
	}
}
