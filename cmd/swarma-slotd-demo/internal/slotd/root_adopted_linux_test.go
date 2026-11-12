//go:build linux

package slotd

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Root suite for the adopted (persistent, externally provisioned) account:
// the G2 agent account that slotd verifies and never creates or deletes.

var adoptedFixtureSeq atomic.Uint32

// fixtureGroup adds a system group and removes it at cleanup.
func fixtureGroup(t *testing.T, name string) uint32 {
	t.Helper()
	if out, err := exec.Command("/usr/sbin/groupadd", "--system", name).CombinedOutput(); err != nil {
		t.Fatalf("groupadd %s: %v %s", name, err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/sbin/groupdel", name).CombinedOutput(); err != nil {
			t.Errorf("groupdel %s: %v %s", name, err, out)
		}
	})
	out, err := exec.Command("/usr/bin/getent", "group", name).Output()
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if err != nil || len(fields) < 3 {
		t.Fatal("group lookup", name, err)
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(gid)
}

func runFixture(t *testing.T, path string, args ...string) {
	t.Helper()
	if out, err := exec.Command(path, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %q: %v %s", path, args, err, out)
	}
}

type adoptedHost struct {
	Name    string
	UID     uint32
	KeyFile string
}

// adoptedAccountFixture provisions the account the way the G2 host flow
// renders it ("u <name> <uid>" + "m <name> <socket group>"): own group with
// GID == UID, home "/", nologin, locked, member of the given groups, plus an
// agent key file owned by it. Cleanup (not slotd) deletes it.
func adoptedAccountFixture(t *testing.T, dir string, groups ...string) adoptedHost {
	t.Helper()
	var uid uint32
	for {
		uid = 61000 + adoptedFixtureSeq.Add(1)
		if exec.Command("/usr/bin/getent", "passwd", strconv.FormatUint(uint64(uid), 10)).Run() != nil && exec.Command("/usr/bin/getent", "group", strconv.FormatUint(uint64(uid), 10)).Run() != nil {
			break
		}
	}
	h := adoptedHost{Name: "slotd-agent-" + t19Nonce()[:6], UID: uid}
	n := strconv.FormatUint(uint64(uid), 10)
	runFixture(t, "/usr/sbin/groupadd", "--gid", n, h.Name)
	args := []string{"--system", "--uid", n, "--gid", n, "--no-create-home", "--home-dir", "/", "--shell", "/usr/sbin/nologin"}
	if len(groups) != 0 {
		args = append(args, "--groups", strings.Join(groups, ","))
	}
	runFixture(t, "/usr/sbin/useradd", append(args, h.Name)...)
	t.Cleanup(func() {
		if out, err := exec.Command("/usr/sbin/userdel", h.Name).CombinedOutput(); err != nil {
			t.Errorf("userdel: %v %s", err, out)
		}
		_ = exec.Command("/usr/sbin/groupdel", h.Name).Run()
	})
	h.KeyFile = filepath.Join(dir, "agent-"+h.Name+".key")
	if err := os.WriteFile(h.KeyFile, []byte("fixture agent key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(h.KeyFile, int(uid), int(uid)); err != nil {
		t.Fatal(err)
	}
	return h
}

// declareAdopted makes r's slot the policy's adopted slot for h.
func declareAdopted(t *testing.T, p *policy, r *durableRecord, h adoptedHost, group string, gid uint32) {
	t.Helper()
	p.Adopted = &adoptedAccount{Slot: r.Slot, Name: h.Name, UID: h.UID, SocketGroup: group, SocketGID: gid, KeyFile: h.KeyFile}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	id, err := p.identity(r.Slot)
	if err != nil || !id.adopted() {
		t.Fatal("adopted identity", err)
	}
	r.Identity = id
}

// t19Adopt runs a T19 slot as the adopted account in the wallet peer group,
// so the 0660 root:<peer group> wallet socket is reachable from it.
func t19Adopt(t *testing.T, p *policy, r *durableRecord, dir string, w *t19Wallet) adoptedHost {
	t.Helper()
	h := adoptedAccountFixture(t, dir, w.PeerGroup)
	declareAdopted(t, p, r, h, w.PeerGroup, w.PeerGID)
	return h
}

func passwdLine(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/getent", "passwd", name).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// TestRootAdoptedAccountRules proves, against the real account databases
// and NSS, the adoption rules beside their valid neighbours: the declared
// account in exactly {own, socket group} is adopted without creating
// anything; a third group, an undeclared group in place of the socket group,
// GID != UID and a declared UID that differs from the account's each refuse;
// an undeclared pre-existing account of a worker slot still refuses with
// "unmanaged identity exists".
func TestRootAdoptedAccountRules(t *testing.T) {
	p, r, dir := rootFixture(t)
	socket := "slotd-adopt-wp-" + t19Nonce()[:6]
	socketGID := fixtureGroup(t, socket)
	extra := "slotd-adopt-x-" + t19Nonce()[:6]
	extraGID := fixtureGroup(t, extra)
	h := adoptedAccountFixture(t, dir, socket)
	declareAdopted(t, &p, &r, h, socket, socketGID)
	ctx := context.Background()
	expect := func(step, want string) {
		t.Helper()
		_, err := observeAccounts(ctx, r.Identity)
		if want == "" && err != nil {
			t.Fatalf("%s: valid adopted account refused: %v", step, err)
		}
		if want != "" && (err == nil || err.Error() != want) {
			t.Fatalf("%s: %v, want %q", step, err, want)
		}
	}
	expect("declared", "")
	runFixture(t, "/usr/sbin/usermod", "--append", "--groups", extra, h.Name)
	expect("third group", "supplementary group refused")
	runFixture(t, "/usr/bin/gpasswd", "--delete", h.Name, extra)
	expect("third group removed", "")
	runFixture(t, "/usr/bin/gpasswd", "--delete", h.Name, socket)
	runFixture(t, "/usr/sbin/usermod", "--append", "--groups", extra, h.Name)
	// /etc/group line order decides which of the two refusals is seen first.
	if _, err := observeAccounts(ctx, r.Identity); err == nil || (err.Error() != "socket group membership missing" && err.Error() != "supplementary group refused") {
		t.Fatalf("undeclared group: %v", err)
	}
	runFixture(t, "/usr/bin/gpasswd", "--delete", h.Name, extra)
	runFixture(t, "/usr/sbin/usermod", "--append", "--groups", socket, h.Name)
	expect("socket group restored", "")
	runFixture(t, "/usr/sbin/usermod", "--gid", strconv.FormatUint(uint64(extraGID), 10), h.Name)
	expect("GID != UID", "account identity mismatch")
	runFixture(t, "/usr/sbin/usermod", "--gid", strconv.FormatUint(uint64(h.UID), 10), h.Name)
	expect("GID == UID restored", "")
	// A declaration naming the account with another UID refuses.
	wrong := p
	decl := *p.Adopted
	decl.UID = h.UID + 500
	wrong.Adopted = &decl
	if id, _ := wrong.identity(r.Slot); func() error { _, err := observeAccounts(ctx, id); return err }() == nil {
		t.Fatal("declared UID different from the account admitted")
	}
	// Adoption verifies and creates nothing: the databases are byte-identical
	// afterwards and the receipt covers the existing lines.
	before := [2][]byte{}
	for i, name := range []string{"/etc/passwd", "/etc/group"} {
		before[i], _ = os.ReadFile(name)
	}
	receipt, err := createAccounts(ctx, r.Identity, p.HomeRoot, r.Slot)
	if err != nil || receipt == nil {
		t.Fatalf("adoption: %v", err)
	}
	for i, name := range []string{"/etc/passwd", "/etc/group"} {
		if after, _ := os.ReadFile(name); string(after) != string(before[i]) {
			t.Fatalf("adoption changed %s", name)
		}
	}
	// A declared account that does not exist is never created.
	missing := p
	decl = *p.Adopted
	decl.Name, decl.UID = "slotd-absent-"+t19Nonce()[:6], h.UID+700
	missing.Adopted = &decl
	id, _ := missing.identity(r.Slot)
	if _, err = createAccounts(ctx, id, p.HomeRoot, r.Slot); err == nil || passwdLine(t, decl.Name) != "" {
		t.Fatalf("missing declared account: %v, created %q", err, passwdLine(t, decl.Name))
	}
	// An undeclared pre-existing account (a worker slot's name and UID made by
	// someone else) still refuses.
	worker, err := p.identity(strconv.FormatUint(uint64(7000+fixtureSlot.Add(1)), 10))
	if err != nil || worker.adopted() {
		t.Fatal(err)
	}
	wn := strconv.FormatUint(uint64(worker.UID), 10)
	runFixture(t, "/usr/sbin/groupadd", "--gid", wn, worker.Name)
	runFixture(t, "/usr/sbin/useradd", "--system", "--uid", wn, "--gid", wn, "--no-create-home", "--home-dir", worker.Home, "--shell", "/usr/sbin/nologin", worker.Name)
	t.Cleanup(func() {
		_ = exec.Command("/usr/sbin/userdel", worker.Name).Run()
		_ = exec.Command("/usr/sbin/groupdel", worker.Name).Run()
	})
	if _, err = createAccounts(ctx, worker, p.HomeRoot, strings.TrimPrefix(worker.Name, "worker-slot-")); err == nil || err.Error() != "unmanaged identity exists" {
		t.Fatalf("undeclared pre-existing account: %v", err)
	}
}

// startProbeSlot creates and starts slot r through the engine with the T19
// probe spec as its payload argv and waits for its report.
func startProbeSlot(t *testing.T, engine *lifecycle, r *durableRecord, report string) t19Report {
	t.Helper()
	q := currentCreate(t, r)
	q.NotAfter = time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
	created, code := engine.apply(context.Background(), q)
	if created != nil {
		*r = *created
	}
	if code != "" {
		t.Fatal("create:", code)
	}
	q.Op = "start"
	started, code := engine.apply(context.Background(), q)
	if started != nil {
		*r = *started
	}
	if code != "" {
		t.Fatal("start:", code)
	}
	return awaitT19Report(t, report, 2*time.Minute)
}

// TestRootAdoptedWalletGroup proves the group layer of a REAL 0660
// root:<peer group> wallet socket: from the adopted slot (SupplementaryGroups=
// the declared group) connect works, id -g == own GID and id -G == exactly
// {own, socket GID}, and the key file is read-only; from a worker slot of the
// same policy (no group) connect is refused with EACCES and its unit keeps
// no supplementary group.
func TestRootAdoptedWalletGroup(t *testing.T) {
	p, r, dir := rootFixture(t)
	w, _, _ := t19Wallets(t)
	t19Adopt(t, &p, &r, dir, w)
	worker := r
	worker.Slot = strconv.FormatUint(uint64(7000+fixtureSlot.Add(1)), 10)
	var err error
	if worker.Identity, err = p.identity(worker.Slot); err != nil || worker.Identity.adopted() {
		t.Fatal(err)
	}
	// One argv serves both slots: each probe reports into its own home.
	setT19Policy(t, &p, dir)
	p.Egress = nil
	engine, _, effects := realEngine(t, p, &r, dir)
	accountCleanup(t, effects, &worker)
	reports := map[string]t19Report{}
	for _, slot := range []*durableRecord{&r, &worker} {
		spec := t19Spec{Report: filepath.Join(slot.Identity.Home, "report"), Pathnames: []string{t19WalletSock}, Wallet: t19WalletSock, Frame: t19WalletReq, Hold: true}
		if slot.Identity.adopted() {
			spec.KeyFile = slot.Identity.KeyFile
		}
		engine.policy.Payload.Argv = append([]string{p.Payload.Path}, t19SpecArgv(spec)...)
		effects.policy = engine.policy
		reports[slot.Slot] = startProbeSlot(t, engine, slot, spec.Report)
	}
	adopted, plain := reports[r.Slot], reports[worker.Slot]
	groups := groupSet(adopted.Groups)
	want := []int{int(w.PeerGID), int(r.Identity.UID)}
	slices.Sort(want)
	if adopted.WalletErr != "ok" || adopted.Pathnames[t19WalletSock] != "ok" || !w.sawPeer(r.Identity.UID) {
		t.Errorf("adopted slot wallet %s / %s, want ok", adopted.WalletErr, adopted.Pathnames[t19WalletSock])
	}
	if adopted.GID != int(r.Identity.UID) || !slices.Equal(groups, want) {
		t.Errorf("adopted gid %d groups %v, want %d and %v", adopted.GID, groups, r.Identity.UID, want)
	}
	if adopted.KeyRead != "ok" || adopted.KeyWrite != "EROFS" || adopted.KeyChmod != "EROFS" {
		t.Errorf("key read %s write %s chmod %s, want ok/EROFS/EROFS", adopted.KeyRead, adopted.KeyWrite, adopted.KeyChmod)
	}
	if plain.WalletErr != "EACCES" || plain.Pathnames[t19WalletSock] != "EACCES" || w.sawPeer(worker.Identity.UID) {
		t.Errorf("worker slot wallet %s / %s, want EACCES", plain.WalletErr, plain.Pathnames[t19WalletSock])
	}
	if plain.GID != int(worker.Identity.UID) || !slices.Equal(groupSet(plain.Groups), []int{int(worker.Identity.UID)}) {
		t.Errorf("worker gid %d groups %v, want exactly own %d", plain.GID, plain.Groups, worker.Identity.UID)
	}
	ctx := context.Background()
	for _, slot := range []*durableRecord{&r, &worker} {
		values, err := unitProperties(ctx, slot.Identity)
		if err != nil {
			t.Fatal(err)
		}
		wantGroups := ""
		if slot.Identity.adopted() {
			wantGroups = w.PeerGroup
		}
		if values["SupplementaryGroups"] != wantGroups {
			t.Errorf("slot %s SupplementaryGroups %q, want %q", slot.Slot, values["SupplementaryGroups"], wantGroups)
		}
		if err = verifyUnitProperties(values, engine.policy, slot); err != nil {
			t.Errorf("slot %s readback: %v", slot.Slot, err)
		}
		q := request{Op: "stop", Slot: slot.Slot}
		if _, code := engine.apply(ctx, q); code != "" {
			t.Fatal("stop:", code)
		}
	}
}

// groupSet is the sorted, de-duplicated group list: id -G as a set.
func groupSet(groups []int) []int {
	out := slices.Clone(groups)
	slices.Sort(out)
	return slices.Compact(out)
}

// plantProcess starts a process of uid outside any slot unit.
func plantProcess(t *testing.T, uid uint32) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/usr/bin/sleep", "600")
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// TestRootAdoptedRetirement proves conditions 3, 7 and 10 on a real slot:
// retirement keeps the account, kills its processes and removes the per-slot
// home; the no-residue gate passes after a clean retirement and the account
// is reused; a planted residue file, a planted lingering process and linger
// each refuse reuse until removed; residue planted during a rental fails the
// retirement and forbids reuse until a clean retry; a second create of the
// adopted slot refuses while it is alive.
func TestRootAdoptedRetirement(t *testing.T) {
	p, r, dir := rootFixture(t)
	socket := "slotd-adopt-wp-" + t19Nonce()[:6]
	socketGID := fixtureGroup(t, socket)
	h := adoptedAccountFixture(t, dir, socket)
	declareAdopted(t, &p, &r, h, socket, socketGID)
	report := filepath.Join(r.Identity.Home, "report")
	setT19Policy(t, &p, dir, t19SpecArgv(t19Spec{Report: report, Hold: true})...)
	p.Egress = nil
	engine, _, _ := realEngine(t, p, &r, dir)
	engine.diagnostic = func(slot string, e error) { t.Logf("slot=%s private lifecycle cause: %v", slot, e) }
	ctx := context.Background()
	account := passwdLine(t, h.Name)
	if account == "" {
		t.Fatal("fixture account missing")
	}
	apply := func(op string, q request) errorCode {
		t.Helper()
		q.Op = op
		got, code := engine.apply(ctx, q)
		if got != nil {
			r = *got
		}
		return code
	}
	retired := func(step string) {
		t.Helper()
		if passwdLine(t, h.Name) != account {
			t.Fatalf("%s: retirement deleted or changed the adopted account", step)
		}
		if _, err := os.Lstat(r.Identity.Home); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: per-slot home survived: %v", step, err)
		}
		if err := adoptedNoResidue(ctx, r.Identity); err != nil {
			t.Fatalf("%s: clean retirement left residue: %v", step, err)
		}
	}
	// Every create is freshly issued (5 s freshness window) so each refusal
	// below is the named refusal, never a stale-request rejection.
	notAfter := time.Now().UTC().Add(20 * time.Minute).Truncate(time.Second)
	fresh := func(bootstrap string) request {
		q := currentCreate(t, &r)
		q.NotAfter, q.Bootstrap, q.BootstrapSHA256 = notAfter, []byte(bootstrap), digest([]byte(bootstrap))
		return q
	}
	expectCode := func(step, op string, q request, want errorCode) {
		t.Helper()
		if code := apply(op, q); code != want {
			t.Fatalf("%s: %s code %q, want %q", step, op, code, want)
		}
	}
	// Rental 1, with the second-create refusals while it is alive.
	q := fresh("renter one")
	expectCode("rental 1", "create", q, "")
	expectCode("second create while created", "create", fresh("renter two"), conflict)
	expectCode("rental 1", "start", q, "")
	awaitT19Report(t, report, time.Minute)
	expectCode("second create while running", "create", fresh("renter two"), invalidState)
	expectCode("rental 1", "stop", q, "")
	expectCode("rental 1", "destroy", q, "")
	retired("rental 1")

	// Planted residue refuses reuse; removing it re-admits.
	plant := filepath.Join("/var/tmp", "slotd-residue-"+t19Nonce())
	if err := os.WriteFile(plant, []byte("residue\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(plant) })
	if err := os.Chown(plant, int(h.UID), int(h.UID)); err != nil {
		t.Fatal(err)
	}
	if err := adoptedNoResidue(ctx, r.Identity); err == nil || !strings.Contains(err.Error(), plant) {
		t.Fatalf("planted file: gate %v", err)
	}
	expectCode("reuse over a planted residue file", "create", fresh("renter two"), internalError)
	if r.Binding.State != destroyed {
		t.Fatalf("refused reuse changed the record: %s", r.Binding.State)
	}
	if err := os.Remove(plant); err != nil {
		t.Fatal(err)
	}
	// A lingering process of the UID refuses reuse.
	proc := plantProcess(t, h.UID)
	if err := adoptedNoResidue(ctx, r.Identity); err == nil || err.Error() != "adopted UID processes remain" {
		t.Fatalf("planted process: gate %v", err)
	}
	expectCode("reuse beside a lingering process", "create", fresh("renter two"), internalError)
	_ = proc.Process.Kill()
	_ = proc.Wait()
	// Linger enabled refuses reuse.
	linger := "/var/lib/systemd/linger/" + h.Name
	if err := os.MkdirAll(filepath.Dir(linger), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linger, nil, 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(linger) })
	if err := adoptedNoResidue(ctx, r.Identity); err == nil || err.Error() != "adopted account linger enabled" {
		t.Fatalf("linger: gate %v", err)
	}
	expectCode("reuse with linger enabled", "create", fresh("renter two"), internalError)
	if err := os.Remove(linger); err != nil {
		t.Fatal(err)
	}

	// Rental 2 reuses the account after the clean state is restored. Residue
	// planted during it fails the retirement, which then forbids reuse until
	// the residue is gone and the retirement is retried.
	q2 := fresh("renter two")
	expectCode("clean reuse", "create", q2, "")
	during := filepath.Join("/var/tmp", "slotd-residue-"+t19Nonce())
	if err := os.WriteFile(during, []byte("residue\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(during) })
	if err := os.Chown(during, int(h.UID), int(h.UID)); err != nil {
		t.Fatal(err)
	}
	expectCode("retirement over residue", "destroy", q2, internalError)
	if r.Binding.State != failed {
		t.Fatalf("retirement over residue left state %s", r.Binding.State)
	}
	expectCode("reuse after a failed retirement", "create", fresh("renter three"), invalidState)
	if passwdLine(t, h.Name) != account {
		t.Fatal("failed retirement changed the adopted account")
	}
	if err := os.Remove(during); err != nil {
		t.Fatal(err)
	}
	expectCode("clean retirement retry", "destroy", q2, "")
	retired("rental 2")
}
