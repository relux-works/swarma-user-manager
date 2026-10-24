package updateproof

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type signedFixture struct {
	t        *testing.T
	dir      string
	profile  Profile
	baseline Baseline
	inv      Invocation
	bundle   Bundle
	clock    Clock
	release  string
}

func testCommand(t *testing.T, argv ...string) []byte {
	t.Helper()
	c := exec.Command(argv[0], argv[1:]...)
	c.Env = []string{"PATH=/usr/bin:/bin"}
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("fixture command %s: %v %s", argv[0], e, b)
	}
	return b
}
func toolFixture(t *testing.T, path string) Tool {
	t.Helper()
	p, e := filepath.EvalSymlinks(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return Tool{Path: p, SHA256: Digest(b)}
}
func newSignedFixture(t *testing.T) *signedFixture {
	t.Helper()
	d := t.TempDir()
	os.Chmod(d, 0700)
	testCommand(t, "/usr/bin/gpg", "--no-options", "--homedir", d, "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "A3 synthetic fixture <fixture@invalid>", "rsa2048", "sign", "0")
	// Record and stop only this fixture's own gpg-agent PID, never a shared agent.
	socket := strings.TrimSpace(string(testCommand(t, "/usr/bin/gpgconf", "--homedir", d, "--list-dirs", "agent-socket")))
	c, e := net.Dial("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	rd := bufio.NewReader(c)
	rd.ReadString('\n')
	fmt.Fprintln(c, "GETINFO pid")
	line, e := rd.ReadString('\n')
	c.Close()
	if e != nil || !strings.HasPrefix(line, "D ") {
		t.Fatalf("fixture agent PID: %q %v", line, e)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "D ")))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if p, e := os.FindProcess(pid); e == nil {
			_ = p.Kill()
		}
	})
	key := testCommand(t, "/usr/bin/gpg", "--no-options", "--homedir", d, "--batch", "--export")
	listing := string(testCommand(t, "/usr/bin/gpg", "--no-options", "--homedir", d, "--batch", "--with-colons", "--list-keys"))
	fpr := ""
	for _, l := range strings.Split(listing, "\n") {
		f := strings.Split(l, ":")
		if len(f) > 9 && f[0] == "fpr" {
			fpr = f[9]
			break
		}
	}
	if fpr == "" {
		t.Fatal("missing fixture signer")
	}
	keypath := filepath.Join(d, "pinned.gpg")
	os.WriteFile(keypath, key, 0600)
	now := time.Now().UTC().Truncate(time.Second)
	data := []byte("authenticated installed fixture\n")
	deb := makeDeb(t, "fixture", "2", "amd64", data)
	idx := fmt.Sprintf("Package: fixture\nVersion: 2\nArchitecture: amd64\nFilename: pool/main/f/fixture.deb\nSize: %d\nSHA256: %s\n\n", len(deb), Digest(deb))
	ip := "main/binary-amd64/Packages"
	p := Profile{FutureSkewConfirmed: true, Origin: "Fixture", Suite: "fixture-updates", Codename: "fixture", Architecture: "amd64", Component: "main", IndexPath: ip, Keyring: FilePin{keypath, Digest(key)}, GPGV: toolFixture(t, "/usr/bin/gpgv"), MaxAge: 24 * time.Hour, FutureSkew: 5 * time.Minute, Limits: Limits{Bytes: 8 << 20, Entries: 100, Members: 100}, Signers: []Signer{{Fingerprint: fpr, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}}, Mappings: []Mapping{{Path: "/usr/lib/fixture", Package: "fixture", Architecture: "amd64", Mode: 0644}}, fileOwner: uint32(os.Getuid())}
	before, after := sampleSnapshot("1"), sampleSnapshot("2")
	after.Packages[0].ArchiveSHA256 = Digest(deb)
	after.Leaves[0].SHA256 = Digest(data)
	base := Baseline{Leaves: append([]Leaf(nil), before.Leaves...), Packages: append([]Package(nil), before.Packages...), ReleaseDate: now.Add(-2 * time.Hour), ReleaseSHA256: Digest([]byte("previous release")), LastTime: now.Add(-time.Minute)}
	f := &signedFixture{t: t, dir: d, profile: p, baseline: base, inv: Invocation{ID: ID{"fixture-boot", 1, "invocation"}, Before: before, After: after, Status: "complete"}, bundle: Bundle{Index: []byte(idx), Archives: map[string][]byte{"fixture:amd64": deb}, Installed: map[string]Installed{"/usr/lib/fixture": {Bytes: data, Mode: 0644, MD5: fmt.Sprintf("%x", md5.Sum(data))}}}, clock: Clock{Now: now, Source: "platform-time-policy", Trusted: true}}
	f.release = fmt.Sprintf("Origin: Fixture\nSuite: fixture-updates\nCodename: fixture\nArchitectures: amd64\nComponents: main\nDate: %s\nValid-Until: %s\nSHA256:\n %s %d %s\n", now.Add(-time.Hour).Format(time.RFC1123Z), now.Add(time.Hour).Format(time.RFC1123Z), Digest([]byte(idx)), len(idx), ip)
	f.sign(false)
	return f
}
func (f *signedFixture) sign(clear bool) {
	p := filepath.Join(f.dir, "Release")
	os.WriteFile(p, []byte(f.release), 0600)
	sig := p + ".sig"
	args := []string{"/usr/bin/gpg", "--no-options", "--homedir", f.dir, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA256", "--output", sig, "--detach-sign", p}
	if clear {
		args[len(args)-2] = "--clearsign"
	}
	testCommand(f.t, args...)
	b, _ := os.ReadFile(sig)
	if clear {
		f.bundle.Release = b
		f.bundle.Signature = nil
	} else {
		f.bundle.Release = []byte(f.release)
		f.bundle.Signature = b
	}
}
func makeTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for n, b := range files {
		if e := tw.WriteHeader(&tar.Header{Name: n, Mode: 0644, Size: int64(len(b)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return out.Bytes()
}
func makeDeb(t *testing.T, name, version, arch string, data []byte) []byte {
	return makeDebAt(t, name, version, arch, data, "usr/lib/fixture")
}
func makeDebAt(t *testing.T, name, version, arch string, data []byte, leaf string) []byte {
	ctrl := makeTar(t, map[string][]byte{"control": []byte(fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\n", name, version, arch)), "md5sums": []byte(fmt.Sprintf("%x  %s\n", md5.Sum(data), leaf))})
	payload := makeTar(t, map[string][]byte{leaf: data})
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		data []byte
	}{{"debian-binary", []byte("2.0\n")}, {"control.tar.gz", ctrl}, {"data.tar.gz", payload}} {
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", m.name+"/", 0, 0, 0, "100644", len(m.data))
		b.Write(m.data)
		if len(m.data)%2 != 0 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// Claim: a real synthetic signed release authenticates the complete local chain;
// changing one independent link/authority/time condition refuses exactly that
// gate and returns no evidence. No package is installed or script executed.
func TestVerifierRefusals(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	valid := func() {
		t.Helper()
		if _, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock); e != nil {
			t.Fatalf("positive control: %v", e)
		}
	}
	valid()
	cases := []struct {
		name string
		code Refusal
		edit func()
	}{
		{"UpdateArchiveChainBreakRefused_index", ErrChain, func() {
			f.bundle.Index = []byte(strings.Replace(string(f.bundle.Index), "pool/main/f/", "pool/main/g/", 1))
		}},
		{"UpdateArchiveChainBreakRefused_deb", ErrChain, func() {
			f.bundle.Archives["fixture:amd64"] = makeDeb(t, "fixture", "2", "amd64", f.bundle.Installed["/usr/lib/fixture"].Bytes)
			f.bundle.Archives["fixture:amd64"][24] = '9'
		}},
		{"UpdateUnpackagedLeafRefused", ErrOwnership, func() { f.inv.After.Leaves[0].Package = "foreign" }},
		{"UpdateUnknownPackageRefused", ErrScope, func() { f.profile.Mappings = nil }},
		{"UpdateInstalledChecksumMismatchRefused_sha256", ErrChecksum, func() {
			v := f.bundle.Installed["/usr/lib/fixture"]
			v.Bytes = []byte("modified")
			f.bundle.Installed["/usr/lib/fixture"] = v
		}},
		{"UpdateInstalledChecksumMismatchRefused_missing_md5", ErrChecksum, func() {
			v := f.bundle.Installed["/usr/lib/fixture"]
			v.MD5 = ""
			f.bundle.Installed["/usr/lib/fixture"] = v
		}},
		{"UpdateOfflineMissingEvidenceRefused", ErrMissing, func() { delete(f.bundle.Archives, "fixture:amd64") }},
		{"UpdateKeyringOrVerifierDriftRefused_keyring", ErrTool, func() { f.profile.Keyring.SHA256 = Digest([]byte("changed keyring")) }},
		{"UpdateKeyringOrVerifierDriftRefused_verifier", ErrTool, func() { f.profile.GPGV.SHA256 = Digest([]byte("changed verifier")) }},
		{"UpdateUnsignedOrExpiredRefused_unknown_time", ErrTime, func() { f.clock.Trusted = false }},
		{"UpdateUnsignedOrExpiredRefused_rollback_clock", ErrTime, func() { f.clock.Now = f.baseline.LastTime.Add(-time.Second) }},
		{"UpdateUnsignedOrExpiredRefused_expired", ErrTime, func() { f.clock.Now = f.clock.Now.Add(2 * time.Hour) }},
		{"UpdateUnsignedOrExpiredRefused_future", ErrTime, func() {
			f.release = strings.Replace(f.release, "Date: "+f.clock.Now.Add(-time.Hour).Format(time.RFC1123Z), "Date: "+f.clock.Now.Add(10*time.Minute).Format(time.RFC1123Z), 1)
			f.sign(false)
		}},
		{"UpdateUnsignedOrExpiredRefused_unsigned", ErrTrust, func() { f.bundle.Signature = nil }},
		{"UpdateUnsignedOrExpiredRefused_signer", ErrTrust, func() { f.profile.Signers[0].Fingerprint = strings.Repeat("A", 40) }},
		{"UpdateUnsignedOrExpiredRefused_equivocation", ErrTime, func() {
			f.baseline.ReleaseDate = f.clock.Now.Add(-time.Hour)
			f.baseline.ReleaseSHA256 = Digest([]byte("different release"))
		}},
		{"UpdateUnsignedOrExpiredRefused_age_policy", ErrTime, func() { f.profile.MaxAge = 0 }},
		{"UpdateDowngradeRefused", ErrRollback, func() { f.baseline.Packages[0].Version = "1:9" }},
		{"UpdateDowngradeRefused_reinstall", ErrRollback, func() { f.baseline.Packages[0].Version = "2" }},
		{"UpdateHookGapRefused", ErrGap, func() { f.inv.Status = "failed" }},
	}
	cases = append(cases, struct {
		name string
		code Refusal
		edit func()
	}{"UpdateArchiveChainBreakRefused_control", ErrChain, func() { f.rechain(makeDeb(t, "foreign", "2", "amd64", f.bundle.Installed["/usr/lib/fixture"].Bytes)) }})
	cases = append(cases, struct {
		name string
		code Refusal
		edit func()
	}{"UpdateInstalledChecksumMismatchRefused_dpkg_sha256", ErrChecksum, func() {
		v := f.bundle.Installed["/usr/lib/fixture"]
		v.SHA256 = Digest([]byte("different"))
		f.bundle.Installed["/usr/lib/fixture"] = v
	}})
	cases = append(cases, struct {
		name string
		code Refusal
		edit func()
	}{"UpdateUnsignedOrExpiredRefused_malformed_expiry", ErrTime, func() {
		f.release = strings.Replace(f.release, "Valid-Until: "+f.clock.Now.Add(time.Hour).Format(time.RFC1123Z), "Valid-Until: invalid", 1)
		f.sign(false)
	}})
	cases = append(cases, struct {
		name string
		code Refusal
		edit func()
	}{"UpdateScopeExpansionRefused", ErrScope, func() { f.inv.Before.Leaves[0].SHA256 = Digest([]byte("unrecorded prior change")) }})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, b, i, u, clock, release := cloneFixture(f)
			c.edit()
			ev, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock)
			if e != c.code || !reflect.DeepEqual(ev, Evidence{}) {
				t.Fatalf("got evidence=%+v error=%v want %v", ev, e, c.code)
			}
			f.profile, f.baseline, f.inv, f.bundle, f.clock, f.release = p, b, i, u, clock, release
			f.sign(false)
			valid()
		})
	}
	f.sign(true)
	valid()
}
func cloneFixture(f *signedFixture) (Profile, Baseline, Invocation, Bundle, Clock, string) {
	p := f.profile
	p.Signers = append([]Signer(nil), p.Signers...)
	p.Mappings = append([]Mapping(nil), p.Mappings...)
	b := f.baseline
	b.Packages = append([]Package(nil), b.Packages...)
	b.Leaves = append([]Leaf(nil), b.Leaves...)
	i := f.inv
	i.Before.Packages = append([]Package(nil), i.Before.Packages...)
	i.Before.Leaves = append([]Leaf(nil), i.Before.Leaves...)
	i.After.Packages = append([]Package(nil), i.After.Packages...)
	i.After.Leaves = append([]Leaf(nil), i.After.Leaves...)
	u := f.bundle
	u.Release = bytes.Clone(u.Release)
	u.Signature = bytes.Clone(u.Signature)
	u.Index = bytes.Clone(u.Index)
	u.Archives = map[string][]byte{}
	for k, v := range f.bundle.Archives {
		u.Archives[k] = bytes.Clone(v)
	}
	u.Installed = map[string]Installed{}
	for k, v := range f.bundle.Installed {
		v.Bytes = bytes.Clone(v.Bytes)
		u.Installed[k] = v
	}
	return p, b, i, u, f.clock, f.release
}

// Claim: Debian numeric, epoch, tilde and revision boundaries disagree with
// lexical ordering where appropriate; malformed inputs are not valid versions.
func TestDebianVersionOrdering(t *testing.T) {
	for _, c := range [][2]string{{"1.9", "1.10"}, {"1~rc1", "1"}, {"9", "1:1"}, {"1-2", "1-10"}, {"1-1~a", "1-1"}} {
		if CompareVersions(c[0], c[1]) >= 0 || CompareVersions(c[1], c[0]) <= 0 {
			t.Fatal(c)
		}
	}
	if CompareVersions("1.0", "1.0-0") != 0 {
		t.Fatal("implicit revision")
	}
}

// Claim: batch ID association/deduplication cannot hide an intervening downgrade;
// a single authentic invocation is the nearby control, not an accepted update.
func TestUpdateBatchChronology(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	batch := Batch{ID: f.inv.ID, Invocations: []Invocation{f.inv}}
	bundles := map[ID]Bundle{f.inv.ID: f.bundle}
	if _, e := VerifyBatch(ctx, f.profile, f.baseline, batch, bundles, f.clock); e != nil {
		t.Fatal(e)
	}
	batch.ID = ID{"fixture-boot", 1, "aggregate"}
	i := f.inv
	i.ID.Sequence = 2
	i.Parent = batch.ID
	batch.Invocations = []Invocation{i, i}
	bundles = map[ID]Bundle{i.ID: f.bundle}
	if _, e := VerifyBatch(ctx, f.profile, f.baseline, batch, bundles, f.clock); e != ErrGap {
		t.Fatalf("merged IDs: %v", e)
	}
	batch.Invocations = []Invocation{i}
	if _, e := VerifyBatch(ctx, f.profile, f.baseline, batch, bundles, f.clock); e != nil {
		t.Fatalf("aggregate control: %v", e)
	}
	j := i
	j.ID.Sequence = 3
	j.Before = i.After
	j.After = sampleSnapshot("1")
	batch.Invocations = append(batch.Invocations, j)
	bundles[j.ID] = f.bundle
	if _, e := VerifyBatch(ctx, f.profile, f.baseline, batch, bundles, f.clock); e != ErrRollback {
		t.Fatalf("intervening downgrade: %v", e)
	}
}
func (f *signedFixture) rechain(deb []byte) {
	old := f.bundle.Archives["fixture:amd64"]
	index := strings.Replace(string(f.bundle.Index), Digest(old), Digest(deb), 1)
	index = strings.Replace(index, fmt.Sprintf("Size: %d", len(old)), fmt.Sprintf("Size: %d", len(deb)), 1)
	f.release = strings.Replace(f.release, fmt.Sprintf("%s %d %s", Digest(f.bundle.Index), len(f.bundle.Index), f.profile.IndexPath), fmt.Sprintf("%s %d %s", Digest([]byte(index)), len(index), f.profile.IndexPath), 1)
	f.bundle.Index = []byte(index)
	f.bundle.Archives["fixture:amd64"] = deb
	f.inv.After.Packages[0].ArchiveSHA256 = Digest(deb)
	f.sign(false)
}

// Claim: an apt unpack/configure pair retains the intermediate package state,
// but only a fully configured final snapshot can yield complete batch evidence.
func TestUpdateBatchUnpackConfigure(t *testing.T) {
	f := newSignedFixture(t)
	batchID := ID{"fixture-boot", 1, "aggregate"}
	unpack := f.inv
	unpack.ID.Sequence = 2
	unpack.Parent = batchID
	unpack.After = sampleSnapshot("2")
	unpack.After.Packages[0].ArchiveSHA256 = f.inv.After.Packages[0].ArchiveSHA256
	unpack.After.Leaves = f.inv.After.Leaves
	unpack.After.Packages[0].Status = "unpacked"
	unpack.After.PendingTriggers = true
	configure := f.inv
	configure.ID.Sequence = 3
	configure.Parent = batchID
	configure.Before = unpack.After
	batch := Batch{ID: batchID, Invocations: []Invocation{unpack, configure}}
	bundles := map[ID]Bundle{unpack.ID: f.bundle, configure.ID: f.bundle}
	if _, e := VerifyBatch(context.Background(), f.profile, f.baseline, batch, bundles, f.clock); e != nil {
		t.Fatal(e)
	}
	batch.Invocations = batch.Invocations[:1]
	delete(bundles, configure.ID)
	if _, e := VerifyBatch(context.Background(), f.profile, f.baseline, batch, bundles, f.clock); e != ErrGap {
		t.Fatalf("partial transaction: %v", e)
	}
	if PlatformTime().Trusted || PlatformTime().Source != "unknown" {
		t.Fatal("fabricated platform time")
	}
}

// Claim: the native profile accepts only the named Ubuntu/official-archive
// subset. Generic fixture verification itself grants no native deployment.
func TestUpdateSupportedNativeProfile(t *testing.T) {
	p := Profile{MaxAge: UbuntuReleaseMaxAge, P7Deadline: RevocationResponseDeadline, Distribution: "ubuntu", Release: "26.04", Architecture: "amd64", Origin: "Ubuntu", Component: "main", Codename: "approved", Suite: "approved-security"}
	if !supportedNativeProfile(p) {
		t.Fatal("approved control refused")
	}
	for _, edit := range []func(*Profile){func(p *Profile) { p.Origin = "PPA" }, func(p *Profile) { p.Suite = "other" }, func(p *Profile) { p.Component = "universe" }, func(p *Profile) { p.Architecture = "arm64" }, func(p *Profile) { p.Release = "24.04" }, func(p *Profile) { p.MaxAge = 8 * 24 * time.Hour }, func(p *Profile) { p.P7Deadline = 6 * time.Minute }} {
		q := p
		edit(&q)
		if supportedNativeProfile(q) {
			t.Fatal("unsupported native profile admitted")
		}
	}
	for _, v := range []string{"1-", "1a:2", "-1", "1 space", ""} {
		if validVersion(v) {
			t.Fatal("malformed Debian version", v)
		}
	}
}

// Claim: identical-archive reinstall and bounded absent-Valid-Until offline
// chains pass, but same-version replacement and release replay do not.
func TestUpdateReinstallAndFreshnessControls(t *testing.T) {
	f := newSignedFixture(t)
	ctx := context.Background()
	f.inv.Before = Snapshot{Packages: append([]Package(nil), f.inv.After.Packages...), Leaves: append([]Leaf(nil), f.inv.After.Leaves...)}
	f.baseline.Packages = append([]Package(nil), f.inv.Before.Packages...)
	f.baseline.Leaves = append([]Leaf(nil), f.inv.Before.Leaves...)
	if _, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock); e != nil {
		t.Fatal("identical reinstall", e)
	}
	original := f.baseline.Packages[0].ArchiveSHA256
	other := Digest([]byte("previous accepted archive"))
	f.baseline.Packages[0].ArchiveSHA256 = other
	f.inv.Before.Packages[0].ArchiveSHA256 = other
	if _, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock); e != ErrRollback {
		t.Fatal("same-version archive change", e)
	}
	f.baseline.Packages[0].ArchiveSHA256 = original
	f.inv.Before.Packages[0].ArchiveSHA256 = original
	f.release = strings.Replace(f.release, "Valid-Until: "+f.clock.Now.Add(time.Hour).Format(time.RFC1123Z)+"\n", "", 1)
	f.sign(false)
	if _, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock); e != nil {
		t.Fatal("bounded absent expiry", e)
	}
	f.baseline.ReleaseDate = f.clock.Now
	if _, e := Verify(ctx, f.profile, f.baseline, f.inv, f.bundle, f.clock); e != ErrTime {
		t.Fatal("older release replay", e)
	}
}
