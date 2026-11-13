//go:build linux

package slotd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Proves marker absence, wrong host/bytes, missing root and CI markers alone
// cannot authorize real-host effects; the exact marker is the positive control.
func TestT19RealHostAdmission(t *testing.T) {
	good := func() ([]byte, error) { return []byte("rt-stations\n"), nil }
	if err := t19RealHostAdmission(0, "rt-stations", "rt-stations", good); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		uid        int
		host, flag string
		read       func() ([]byte, error)
	}{
		{"missing marker", 0, "rt-stations", "rt-stations", func() ([]byte, error) { return nil, os.ErrNotExist }},
		{"unreadable marker", 0, "rt-stations", "rt-stations", func() ([]byte, error) { return nil, os.ErrPermission }},
		{"mismatched CLI", 0, "rt-stations", "stations1", good},
		{"nonroot", 1001, "rt-stations", "rt-stations", good},
		{"marker names other host", 0, "stations1", "stations1", good},
		{"missing flag", 0, "rt-stations", "", good},
		{"no newline", 0, "rt-stations", "rt-stations", func() ([]byte, error) { return []byte("rt-stations"), nil }},
		{"extra newline", 0, "rt-stations", "rt-stations", func() ([]byte, error) { return []byte("rt-stations\n\n"), nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if t19RealHostAdmission(tc.uid, tc.host, tc.flag, tc.read) == nil {
				t.Fatal("unsafe admission")
			}
		})
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	t.Setenv("SLOTD_ROOT_TESTS", "1")
	if t19RealHostAdmission(0, "rt-stations", "rt-stations", func() ([]byte, error) { return nil, os.ErrNotExist }) == nil {
		t.Fatal("CI-only environment admitted")
	}
}

// The hosted-root predicate remains separate and refuses workstation and
// self-hosted environments even when real-host admission succeeds.
func TestT19RealHostCannotEnableRootFixtures(t *testing.T) {
	for _, runner := range []string{"", "self-hosted", "rt-stations", "github-hosted "} {
		if rootTestAllowed(0, "true", runner, "1") {
			t.Fatalf("root fixture admitted %q", runner)
		}
	}
	if !rootTestAllowed(0, "true", "github-hosted", "1") {
		t.Fatal("hosted positive neighbour refused")
	}
}

// An independent contract oracle pins every scalar. In particular, accepting
// AF_NETLINK is forbidden even if both consumers share the weakened table.
func TestT19SharedExpectationContract(t *testing.T) {
	want := t19ExpectationTable{PathDenied: []string{"ENOENT", "EACCES"}, Hidden: "ENOENT", Abstract: "EPERM", Connected: "ok", TCPDenied: "timeout", UDPDenied: "EPERM", Families: map[string]string{"netlink": "EAFNOSUPPORT", "packet": "EAFNOSUPPORT", "unix": "ok", "inet": "ok", "inet6": "ok"}, Tamper: map[string]string{"prctl-no-new-privs-0": "EINVAL", "prctl-ambient-net-admin": "EPERM"}, KeyRead: "ok", KeyWrite: "EROFS", KeyChmod: "EROFS"}
	if got := t19Expectations(); !reflect.DeepEqual(got, want) {
		t.Fatalf("shared T19 expectation contract weakened: got %+v want %+v", got, want)
	}
}

// Both actual T19.2 consumers decide on the same probe report. Every named
// Linux errno (plus missing/custom outcomes) is checked beside valid wallet
// and denial controls. This detects consumer-local overrides, not just table
// wiring. It proves pathname verdict agreement over this bounded corpus;
// fixture-only wallet protocol assertions remain intentionally out of scope.
func TestT19RootAndRealHostReadSameTable(t *testing.T) {
	verdicts := []string{"ok", "ENOENT", "EACCES", "EIO", "", "timeout", "error:custom"}
	for errno := unix.Errno(1); errno < 4096; errno++ {
		if name := unix.ErrnoName(errno); name != "" && !slices.Contains(verdicts, name) {
			verdicts = append(verdicts, name)
		}
	}
	base := t19ValidFacts(t)
	paths := append([]string{"/run/systemd/private"}, base.Spec.Pathnames...)
	for _, path := range paths {
		for _, verdict := range verdicts {
			f := t19ValidFacts(t)
			f.Probe.Pathnames[path] = verdict
			rootAllowed := len(t19RootPathnameProblems(f.Probe, f.Spec.Pathnames)) == 0
			hostAllowed := t19RealHostVerdicts(f)[1].Verdict == t19Pass
			want := verdict == "ENOENT" || verdict == "EACCES"
			if path == t19WalletSock {
				want = verdict == "ok"
			}
			if rootAllowed != hostAllowed || rootAllowed != want {
				t.Fatalf("consumer divergence/contract failure: path=%q verdict=%q root=%v host=%v want=%v", path, verdict, rootAllowed, hostAllowed, want)
			}
		}
	}
}

func t19ContractPolicy(t *testing.T) policy {
	t.Helper()
	p, err := parsePolicy(examplePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	p.Adopted = &adoptedAccount{Slot: "100", Name: "g2-agent", UID: 210001, SocketGroup: "swarma-wallet-peer", SocketGID: 210101, KeyFile: "/var/lib/g2-agent/agent.key"}
	// The adopted IDs must lie outside the ephemeral interval.
	p.UIDBase = 300000
	return p
}
func t19ValidFacts(t *testing.T) t19HostFacts {
	t.Helper()
	p := t19ContractPolicy(t)
	id, err := p.identity("100")
	if err != nil {
		t.Fatal(err)
	}
	plants, abs := t19PlantNames("100")
	ips := []t19Target{{"tcp4", "127.0.0.1:8336", false}, {"tcp6", "[::1]:8336", false}, {"tcp4", "127.0.0.53:53", false}, {"udp4", "127.0.0.53:53", false}, {"tcp4", "127.0.0.1:18336", true}, {"tcp4", "192.0.2.10:443", false}}
	spec, err := t19ExpectedSpec(p, "100", nil, nil, ips)
	if err != nil {
		t.Fatal(err)
	}
	got := t19Report{UID: int(id.UID), GID: int(id.UID), Groups: []int{int(id.UID), int(id.SocketGID)}, KeyRead: "ok", KeyWrite: "EROFS", KeyChmod: "EROFS", Sockets: []string{t19WalletSock}, Pathnames: map[string]string{}, Abstract: map[string]string{"@" + abs: "EPERM"}, Families: map[string]string{"netlink": "EAFNOSUPPORT", "packet": "EAFNOSUPPORT", "unix": "ok", "inet": "ok", "inet6": "ok"}, Tamper: map[string]string{"unshare-user-net": "EPERM", "prctl-no-new-privs-0": "EINVAL", "prctl-ambient-net-admin": "EPERM"}, AfterTamper: map[string]string{"@" + abs: "EPERM"}, IP: map[string]string{}}
	for _, path := range spec.Pathnames {
		got.Pathnames[path] = "ENOENT"
	}
	got.Pathnames[t19WalletSock] = "ok"
	for _, path := range plants {
		got.AfterTamper[path] = "ENOENT"
	}
	for _, ip := range ips {
		v := "timeout"
		if ip.Network == "udp4" {
			v = "EPERM"
		}
		got.IP[ip.Network+" "+ip.Address] = v
	}
	got.IP["tcp4 192.0.2.10:443"] = "ok"
	return t19HostFacts{Spec: spec, Probe: got, View: t19ViewInventory{Sockets: []string{t19WalletSock}, Mounts: []t19Mount{{Point: "/", FSType: "ext4"}}}, Identity: id, Plants: plants, AbstractPlant: abs, HostAbstract: map[string]string{"@" + abs: "ok"}, JournalFound: true, HostEcho: "ok", WalletKind: "STAND_IN", WalletPeer: t19PeerIdentity{UID: 0, GID: 0, PID: 42}, ExpectedPeerUID: 0}
}

// Proves the observer distinguishes real breaches/missing evidence from the
// complete positive fixture. These are evaluator tests, not real-host claims.
func TestT19ObservationalVerdicts(t *testing.T) {
	for _, it := range t19RealHostVerdicts(t19ValidFacts(t)) {
		if it.ID != "T19.6" && it.ID != "T19.10" && it.Verdict != t19Pass && !(it.ID == "T19.5" && it.Verdict == t19StandIn) {
			t.Fatalf("positive fixture: %+v", it)
		}
	}
	for _, tc := range []struct {
		name string
		id   int
		edit func(*t19HostFacts)
	}{
		{"extra socket", 1, func(f *t19HostFacts) {
			f.Probe.Sockets = append(f.Probe.Sockets, "/extra.sock")
			f.View.Sockets = append(f.View.Sockets, "/extra.sock")
		}},
		{"wrong primary GID", 1, func(f *t19HostFacts) { f.Probe.GID = 210101 }},
		{"operator group", 1, func(f *t19HostFacts) { f.Probe.Groups = append(f.Probe.Groups, 999) }},
		{"key writable", 1, func(f *t19HostFacts) { f.Probe.KeyWrite = "ok" }},
		{"pathname missing result", 2, func(f *t19HostFacts) { delete(f.Probe.Pathnames, t19StatusSock) }},
		{"abstract reachable", 3, func(f *t19HostFacts) { f.Probe.Abstract["@"+f.AbstractPlant] = "ok" }},
		{"plant visible", 4, func(f *t19HostFacts) { f.Probe.Pathnames[f.Plants[0]] = "EACCES" }},
		{"wallet unreachable", 5, func(f *t19HostFacts) { f.Probe.Pathnames[t19WalletSock] = "EACCES" }},
		{"unidentified wallet peer", 5, func(f *t19HostFacts) { f.WalletPeer.PID = 0 }},
		{"wrong wallet peer", 5, func(f *t19HostFacts) { f.WalletPeer.UID = 1000 }},
		{"no journal", 7, func(f *t19HostFacts) { f.JournalFound = false }},
		{"netlink reachable", 8, func(f *t19HostFacts) { f.Probe.Families["netlink"] = "ok" }},
		{"tamper succeeds", 9, func(f *t19HostFacts) { f.Probe.Tamper["unshare-user-net"] = "ok" }},
		{"status visible", 11, func(f *t19HostFacts) { f.Probe.Pathnames[t19StatusSock] = "ok" }},
		{"loopback reachable", 12, func(f *t19HostFacts) { f.Probe.IP["tcp4 127.0.0.1:8336"] = "ok" }},
		{"immediate TCP refusal is insufficient", 12, func(f *t19HostFacts) { f.Probe.IP["tcp4 127.0.0.1:8336"] = "ECONNREFUSED" }},
		{"gateway blocked", 13, func(f *t19HostFacts) { f.Probe.IP["tcp4 192.0.2.10:443"] = "timeout" }},
		{"extra unit property", 13, func(f *t19HostFacts) { f.UnitError = "extra property" }},
		{"wrong ExecStart", 13, func(f *t19HostFacts) { f.ExecError = "wrong payload" }},
		{"missing NFT", 13, func(f *t19HostFacts) { f.NFTError = "absent" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := t19ValidFacts(t)
			tc.edit(&f)
			if it := t19RealHostVerdicts(f)[tc.id-1]; it.Verdict != t19Fail {
				t.Fatalf("breach admitted: %+v", it)
			}
		})
	}
}

// Proves the closed property projection rejects extra, missing, duplicate and
// byte-different scalar values, while accepting systemd's reordered deny set.
func TestT19StrictPropertyTemplate(t *testing.T) {
	p := t19ContractPolicy(t)
	id, err := p.identity("100")
	if err != nil {
		t.Fatal(err)
	}
	r := durableRecord{Identity: id, UnitToken: strings.Repeat("a", 32), UnitRuntimeUS: 123456789}
	expected, err := t19ExpectedProperties(p, r)
	if err != nil {
		t.Fatal(err)
	}
	raw := t19PropertyBytes(expected)
	if _, err = t19CompareProperties(raw, expected); err != nil {
		t.Fatal(err)
	}
	reordered := bytes.Replace(raw, []byte("IPAddressDeny=0.0.0.0/0 ::/0\n"), []byte("IPAddressDeny=::/0 0.0.0.0/0\n"), 1)
	if bytes.Equal(reordered, raw) {
		t.Fatal("deny-set control did not change the template")
	}
	if _, err = t19CompareProperties(reordered, expected); err != nil {
		t.Fatalf("systemd 259.9 deny-set order refused: %v", err)
	}
	for name, changed := range map[string][]byte{
		"extra":      append(slices.Clone(raw), []byte("NewProperty=yes\n")...),
		"missing":    bytes.Replace(raw, []byte("PrivateIPC=yes\n"), nil, 1),
		"duplicate":  append(slices.Clone(raw), []byte("PrivateIPC=yes\n")...),
		"whitespace": bytes.Replace(raw, []byte("PrivateIPC=yes"), []byte("PrivateIPC=yes "), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := t19CompareProperties(changed, expected); err == nil {
				t.Fatal("property delta accepted")
			}
		})
	}
	// Every property requested by production's start vector has a template row.
	inv, err := startInvocation(p, "100", record{State: created, PayloadSHA256: p.payloadDigest(), NotAfter: time.Now().Add(time.Minute * 5)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range inv.Args {
		if prop, ok := strings.CutPrefix(arg, "--property="); ok {
			k, _, _ := strings.Cut(prop, "=")
			if k == "CPUQuota" {
				k = "CPUQuotaPerSecUSec"
			}
			if k == "RuntimeMaxSec" {
				k = "RuntimeMaxUSec"
			}
			if _, ok := expected[k]; !ok {
				t.Fatalf("production property has no closed template row: %s", k)
			}
		}
	}
}

// Every row compared with sameWords by the production verifier accepts an equal
// reordered list, but refuses missing, extra and duplicate words. Scalar rows
// retain byte comparison; the raw observed order remains available as evidence.
func TestT19PropertySetSemantics(t *testing.T) {
	for key, words := range map[string][]string{
		"BindPaths":               {"/home/slot:/home/slot:rbind", "/journal:/journal:rbind"},
		"TemporaryFileSystem":     {"/run:ro", "/var:ro"},
		"BindReadOnlyPaths":       {"/etc/passwd:/etc/passwd:rbind", "/etc/group:/etc/group:rbind"},
		"RestrictAddressFamilies": {"AF_UNIX", "AF_INET", "AF_INET6"},
		"IPAddressDeny":           {"0.0.0.0/0", "::/0"},
		"IPAddressAllow":          {"192.0.2.1/32", "2001:db8::1/128"},
	} {
		t.Run(key, func(t *testing.T) {
			expected := map[string]string{key: strings.Join(words, " ")}
			reversed := slices.Clone(words)
			slices.Reverse(reversed)
			for _, tc := range []struct {
				name, actual string
				accept       bool
			}{
				{"unchanged", expected[key], true},
				{"reordered", strings.Join(reversed, " "), true},
				{"word whitespace", strings.Join(reversed, "  "), true},
				{"missing", strings.Join(words[:len(words)-1], " "), false},
				{"extra", expected[key] + " unexpected", false},
				{"duplicate", expected[key] + " " + words[0], false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := t19CompareProperties([]byte(key+"="+tc.actual+"\n"), expected)
					if (err == nil) != tc.accept {
						t.Fatalf("accept=%t, want %t: %v", err == nil, tc.accept, err)
					}
					if err != nil && !strings.Contains(err.Error(), key) {
						t.Fatalf("refused for an unrelated reason: %v", err)
					}
					if got[key] != tc.actual {
						t.Fatalf("observed evidence changed: %q", got[key])
					}
				})
			}
		})
	}
}

// The live-host spec cannot frame an RPC or request a wallet restart/read.
// The original probe source is reused; only the connection/peer sidecar is new.
func TestT19LiveWalletSpecIsConnectionOnly(t *testing.T) {
	p := t19ContractPolicy(t)
	spec, err := t19ExpectedSpec(p, "100", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = t19ConnectionOnlySpec(spec); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*t19Spec){func(s *t19Spec) { s.Wallet = t19WalletSock }, func(s *t19Spec) { s.Frame = "spend" }, func(s *t19Spec) { s.WalletRestart = true }, func(s *t19Spec) { s.Phase1 = "/tmp/restart" }, func(s *t19Spec) { s.KeyFile = "/var/lib/agent-walletd/wallet.dat" }} {
		s := spec
		edit(&s)
		if t19ConnectionOnlySpec(s) == nil {
			t.Fatal("wallet operation admitted")
		}
	}
}

// A real local socket verifies SO_PEERCRED without sending a single byte.
// The fixture has no wallet implementation, RPC or filesystem state to read.
func TestT19WalletHandshakeSendsNoBytes(t *testing.T) {
	path := "@swarma-t19-peer-test-" + t19Nonce()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	result := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			result <- e
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		n, e := c.Read(b[:])
		if n != 0 || !errors.Is(e, io.EOF) {
			result <- fmt.Errorf("handshake sent application data or did not close: n=%d err=%v", n, e)
			return
		}
		result <- nil
	}()
	peer, err := t19ConnectPeer(path)
	if err != nil {
		t.Fatal(err)
	}
	if peer.UID != uint32(os.Getuid()) || peer.GID != uint32(os.Getgid()) || peer.PID != int32(os.Getpid()) {
		t.Fatalf("wrong kernel peer: %+v", peer)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}

func t19SyntheticCI(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	run := []byte(fmt.Sprintf(`{"id":%d,"head_sha":%q,"status":"completed","conclusion":"success","path":".github/workflows/slotd-demo.yml","run_attempt":1,"repository":{"full_name":"relux-works/swarma-user-manager"}}`, t19HostedRun, t19HostedCommit))
	jobs := []byte(fmt.Sprintf(`{"jobs":[{"id":%d,"run_id":%d,"head_sha":%q,"name":"root","status":"completed","conclusion":"success","runner_name":"GitHub Actions 1000055183","labels":["ubuntu-26.04"]}]}`, t19HostedJob, t19HostedRun, t19HostedCommit))
	var log []byte
	for _, name := range t19HostedTests {
		b, _ := json.Marshal(map[string]string{"Action": "pass", "Test": name})
		log = append(log, b...)
		log = append(log, '\n')
	}
	log = append(log, []byte("root test pipeline status 0\n")...)
	return run, jobs, log
}

// Synthetic fixtures exercise the verifier's rejection logic with an injected
// digest pin. Production always uses the audited immutable log SHA256.
func TestT19HostedEvidenceRefusals(t *testing.T) {
	run, jobs, log := t19SyntheticCI(t)
	pin := digest(log)
	if ci := t19VerifyHostedLog(run, jobs, log, pin); !ci.Verified {
		t.Fatal(ci.Error)
	}
	for _, tc := range []struct {
		name           string
		run, jobs, log []byte
		pin            string
	}{
		{"portable-only", run, []byte(`{"jobs":[]}`), log, pin},
		{"wrong tree", bytes.ReplaceAll(run, []byte(t19HostedCommit), []byte(strings.Repeat("a", 40))), jobs, log, pin},
		{"wrong log", run, jobs, append(slices.Clone(log), 'x'), pin},
		{"skipped test", run, jobs, bytes.Replace(log, []byte(`"Action":"pass"`), []byte(`"Action":"skip"`), 1), ""},
		{"failed test", run, jobs, bytes.Replace(log, []byte(`"Action":"pass"`), []byte(`"Action":"fail"`), 1), ""},
		{"missing test", run, jobs, []byte("root test pipeline status 0\n"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pin == "" {
				tc.pin = digest(tc.log)
			}
			if t19VerifyHostedLog(tc.run, tc.jobs, tc.log, tc.pin).Verified {
				t.Fatal("unverified run admitted")
			}
		})
	}
	if t19VerifyHosted(run, jobs, log).Verified {
		t.Fatal("synthetic log passed production pin")
	}
}

func t19ValidReport(t *testing.T) t19RealHostReport {
	t.Helper()
	r := t19NewReport("rt-stations", "100")
	r.WalletKind = "STAND_IN"
	r.Items = t19RealHostVerdicts(t19ValidFacts(t))
	r.PolicySHA256 = strings.Repeat("a", 64)
	r.BinarySHA256 = strings.Repeat("b", 64)
	r.ProbeSHA256 = strings.Repeat("c", 64)
	r.Hosted = t19CIEvidence{Commit: t19HostedCommit, RunID: t19HostedRun, JobID: t19HostedJob, LogSHA256: t19HostedLogHash, Verified: true}
	r.hostedItems()
	r.Cleanup = t19Item{ID: "cleanup", Verdict: t19Pass, Evidence: []t19Evidence{{Claim: "clean fixture"}}}
	r.Restoration = t19Item{ID: "restoration", Verdict: t19Pass, Evidence: []t19Evidence{{Claim: "restoration fixture"}}}
	return r
}

func t19ValidRealReport(t *testing.T) t19RealHostReport {
	t.Helper()
	r := t19ValidReport(t)
	r.Host = "stations1"
	r.WalletKind = "REAL"
	facts := t19ValidFacts(t)
	facts.WalletKind = "REAL"
	r.Items[4] = t19RealHostVerdicts(facts)[4]
	return r
}

// Proves cardinality, status vocabulary, historical tree/run binding and all
// closing gates survive JSON roundtrip; any FAIL or missing restoration blocks.
func TestT19ReportSchemaAndClosingRule(t *testing.T) {
	r := t19ValidRealReport(t)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded t19RealHostReport
	if decoded, err = t19DecodeReport(b); err != nil {
		t.Fatal(err)
	}
	if err = t19ValidateReport(decoded); err != nil {
		t.Fatal(err)
	}
	if t19ReportExit(decoded) != 0 {
		t.Fatal("complete fixture did not close")
	}
	if _, err = t19DecodeReport(bytes.Replace(b, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)); err == nil {
		t.Fatal("unknown report field admitted")
	}
	if _, err = t19DecodeReport(append(slices.Clone(b), b...)); err == nil {
		t.Fatal("multiple report documents admitted")
	}

	for _, tc := range []struct {
		name string
		edit func(*t19RealHostReport)
	}{
		{"item FAIL", func(r *t19RealHostReport) { r.Items[0].Verdict = t19Fail }},
		{"unknown status", func(r *t19RealHostReport) { r.Items[0].Verdict = "UNVERIFIED" }},
		{"hook item PASS", func(r *t19RealHostReport) { r.Items[9].Verdict = t19Pass }},
		{"observational item covered", func(r *t19RealHostReport) { r.Items[0].Verdict = t19Covered }},
		{"duplicate item", func(r *t19RealHostReport) { r.Items[0].ID = "T19.2" }},
		{"missing item", func(r *t19RealHostReport) { r.Items = r.Items[:12] }},
		{"missing evidence", func(r *t19RealHostReport) { r.Items[0].Evidence = nil }},
		{"unverified run", func(r *t19RealHostReport) { r.Hosted.Verified = false }},
		{"different tree", func(r *t19RealHostReport) { r.Hosted.Commit = strings.Repeat("a", 40) }},
		{"different run", func(r *t19RealHostReport) { r.Hosted.RunID++ }},
		{"no binary hash", func(r *t19RealHostReport) { r.BinarySHA256 = "" }},
		{"missing retirement", func(r *t19RealHostReport) { r.Cleanup.Verdict = t19Fail }},
		{"missing restoration", func(r *t19RealHostReport) { r.Restoration.Verdict = t19Fail }},
		{"stand-in mislabelled real", func(r *t19RealHostReport) { *r = t19ValidReport(t); r.WalletKind = "REAL" }},
		{"stations1 stand-in", func(r *t19RealHostReport) { *r = t19ValidReport(t); r.Host = "stations1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := t19ValidRealReport(t)
			tc.edit(&r)
			if t19ReportExit(r) == 0 {
				t.Fatal("invalid report closed matrix item")
			}
		})
	}
}

// Client-state fixtures never instantiate a daemon. They prove lost-create
// cleanup owns only its nonce-bound rental and a pre-existing slot is untouched.
func TestT19RentalOwnershipAndLostCreate(t *testing.T) {
	var current response
	var ops []string
	rental := &t19Rental{Slot: "100"}
	rental.Call = func(_ context.Context, q map[string]any) (response, error) {
		op := q["op"].(string)
		ops = append(ops, op)
		switch op {
		case "status":
			if current.State == "" {
				return response{State: absent}, nil
			}
			return current, nil
		case "create":
			current = rental.Binding
			current.State = created
			return response{}, errors.New("lost response after create")
		case "destroy":
			current.State = destroyed
			return current, nil
		}
		return response{}, errors.New("unexpected op")
	}
	if rental.create(context.Background(), strings.Repeat("a", 64)) == nil {
		t.Fatal("lost create reported success")
	}
	rental.Issued = 0
	if _, err := rental.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ops, []string{"status", "create", "status", "destroy", "status"}) {
		t.Fatalf("unexpected lifecycle %v", ops)
	}
	ops = nil
	rental.Attempted = false
	current.State = created
	if rental.create(context.Background(), strings.Repeat("a", 64)) == nil {
		t.Fatal("existing slot adopted")
	}
	if !slices.Equal(ops, []string{"status"}) {
		t.Fatal("foreign slot mutated")
	}
	rental.Attempted = true
	current.PayloadSHA256 = strings.Repeat("b", 64)
	ops = nil
	if _, err := rental.cleanup(context.Background()); err == nil {
		t.Fatal("foreign binding retired")
	}
	if !slices.Equal(ops, []string{"status"}) {
		t.Fatal("foreign binding mutated")
	}
}

// The production negative control requires a still-valid stopped qualification
// binding. A destroyed/expired slot or unrelated bad_request cannot certify it.
func TestT19ProductionRefusalControl(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   state
		refusal errorCode
		expiry  time.Duration
		want    bool
	}{
		{"bound mismatch", stopped, invalidState, time.Minute * 10, true},
		{"destroyed is not a binding witness", destroyed, invalidState, time.Minute * 10, false},
		{"expired is not a binding witness", stopped, expired, -time.Minute, false},
		{"generic parse refusal is insufficient", stopped, badRequest, time.Minute * 10, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &t19Rental{Slot: "100", Binding: response{Slot: "100", NotAfter: time.Now().Add(tc.expiry).UTC().Format(time.RFC3339), PayloadSHA256: strings.Repeat("a", 64), BootstrapSHA256: strings.Repeat("b", 64)}}
			r.Call = func(_ context.Context, q map[string]any) (response, error) {
				s := r.Binding
				s.State = tc.state
				if q["op"] == "start" {
					s.State = ""
					s.Error = tc.refusal
					return s, errors.New("refused")
				}
				return s, nil
			}
			_, err := t19ProductionRefusal(context.Background(), r, strings.Repeat("c", 64))
			if (err == nil) != tc.want {
				t.Fatalf("control verdict err=%v", err)
			}
		})
	}
}

// Changed qualification identity or policy authority is rejected before effects;
// only the payload may differ, and the exact production bytes must be restored.
func TestT19WindowPolicyBoundary(t *testing.T) {
	prod := t19ContractPolicy(t)
	qual := prod
	qual.Payload.SHA256 = strings.Repeat("a", 64)
	if err := t19WindowPolicies(prod, qual); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*policy){func(p *policy) { p.CallerUser = "other" }, func(p *policy) { p.UIDBase++ }, func(p *policy) { p.Caps.TasksMax++ }, func(p *policy) { p.HomeRoot = "/other" }, func(p *policy) { p.Version = 2 }, func(p *policy) { a := *p.Adopted; a.UID++; p.Adopted = &a }} {
		p := qual
		edit(&p)
		if t19WindowPolicies(prod, p) == nil {
			t.Fatal("policy boundary expanded")
		}
	}
}

// The probe key has the same UID/GID, 0600 and single-link contract as the
// real agent key; root-owned, socket-group-owned and writable substitutes fail.
func TestT19ProbeKeyRealRunShape(t *testing.T) {
	good := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: 210001, Gid: 210001, Nlink: 1}
	if err := t19KeyMetadata(good, 210001); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 0 }, func(s *unix.Stat_t) { s.Gid = 210101 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0640 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0600 }} {
		s := good
		edit(&s)
		if t19KeyMetadata(s, 210001) == nil {
			t.Fatal("non-real-run key shape admitted")
		}
	}
}

// The rt-stations fixture must never replace a live stations1 wallet.
func TestT19StandInHostBoundary(t *testing.T) {
	if t19StandInAdmission("rt-stations", "rt-stations") != nil {
		t.Fatal("positive neighbour refused")
	}
	for _, host := range []string{"stations1", "stations1.example", "rt-stations.example", ""} {
		if t19StandInAdmission(host, host) == nil {
			t.Fatal("stand-in admitted outside rt-stations")
		}
	}
}

// Production responses remain closed and bound to exactly the requested slot.
// A malformed/foreign response cannot authorize any cleanup operation.
func TestT19InstalledWireResponseContract(t *testing.T) {
	p, r := durableFixture(t)
	_ = p
	good := encodeResponse(r.Slot, &r.Binding, "")
	if _, err := t19DecodeWire(good, r.Slot); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte(`{"v":1,"ok":true,"slot":"0","state":"absent"}` + "\n"),
		bytes.TrimSuffix(good, []byte("\n")),
		append(slices.Clone(good), good...),
		[]byte(`{"v":1,"v":1,"ok":true,"slot":"100","state":"absent"}` + "\n"),
		[]byte(`{"v":1,"ok":true,"slot":"100","state":"running"}` + "\n"),
		[]byte(`{"v":1,"ok":true,"slot":"100","state":"invented"}` + "\n"),
	} {
		if _, err := t19DecodeWire(bad, r.Slot); err == nil {
			t.Fatalf("invalid response accepted: %s", bad)
		}
	}
}

// Missing D-Bus evidence must not be interpreted as an empty environment-file
// list just because systemctl omits that empty display row.
func TestT19EnvironmentFilesExplicitReadback(t *testing.T) {
	if t19EmptyEnvironmentFiles([]byte("a(sb) 0\n")) != nil {
		t.Fatal("typed empty array refused")
	}
	for _, bad := range []string{"", "a(sb) 1 \"/etc/secrets\" false\n", "a(sb) 0\nextra\n", "as 0\n"} {
		if t19EmptyEnvironmentFiles([]byte(bad)) == nil {
			t.Fatal("missing/nonempty evidence admitted")
		}
	}
}

// The reviewed inert template names the same observer, real-run account shape
// and connection-only spec as the renderer. Actual host inventories and pins
// are supplied by --prepare; documentation example bytes are never deployed.
func TestT19QualificationPolicyTemplate(t *testing.T) {
	b, err := os.ReadFile("../../../../deploy/slotd-demo/t19-qualification-policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.identity("100")
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "g2-agent" || id.UID != 210001 || id.SocketGID != 210101 || p.Payload.Argv[1] != "slotd-t19-observer" {
		t.Fatal("template lost accepted account/observer shape")
	}
	var spec t19Spec
	if json.Unmarshal([]byte(p.Payload.Argv[2]), &spec) != nil {
		t.Fatal("invalid template spec")
	}
	if err = t19ConnectionOnlySpec(spec); err != nil {
		t.Fatal(err)
	}
	if spec.KeyFile != id.KeyFile || !spec.Inventory || !spec.Families || !spec.Tamper || !spec.Hold {
		t.Fatal("template lost observational probes")
	}
}

// Lost stop/destroy replies are resolved by binding-preserving status rather
// than abandoning an owned slot or destroying a foreign one.
func TestT19RetirementUncertainReplies(t *testing.T) {
	boot, _, err := bootClock()
	if err != nil {
		t.Fatal(err)
	}
	r := &t19Rental{Slot: "100", Attempted: true, Boot: boot, Issued: 0, Binding: response{Slot: "100", NotAfter: time.Now().Add(time.Minute * 10).UTC().Format(time.RFC3339), PayloadSHA256: strings.Repeat("a", 64), BootstrapSHA256: strings.Repeat("b", 64)}}
	current := r.Binding
	current.State = running
	var ops []string
	r.Call = func(_ context.Context, q map[string]any) (response, error) {
		op := q["op"].(string)
		ops = append(ops, op)
		switch op {
		case "status":
			return current, nil
		case "stop":
			current.State = stopped
			return response{}, errors.New("lost stop response")
		case "destroy":
			current.State = destroyed
			return response{}, errors.New("lost destroy response")
		}
		return response{}, errors.New("unexpected")
	}
	if _, err = r.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ops, []string{"status", "stop", "status", "destroy", "status"}) {
		t.Fatalf("unexpected recovery %v", ops)
	}
}

// The real-run key ancestry is exact 0755, not just non-writable to others.
// Descriptor traversal/ACL/symlink refusal is reused from the production loader.
func TestT19ProbeKeyParentShape(t *testing.T) {
	good := unix.Stat_t{Mode: unix.S_IFDIR | 0755, Uid: 0, Gid: 0}
	if err := t19KeyParentMetadata(good); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Mode = unix.S_IFDIR | 0700 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFDIR | 0775 }, func(s *unix.Stat_t) { s.Uid = 210001 }, func(s *unix.Stat_t) { s.Gid = 210101 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0755 }} {
		s := good
		edit(&s)
		if t19KeyParentMetadata(s) == nil {
			t.Fatal("non-real-run parent shape admitted")
		}
	}
}

// Regression for rev236 stand-in-pass-closes: successful stand-in evidence is
// explicitly STAND_IN, exits 2, and never closes. The reviewer's original
// STAND_IN-as-PASS JSON is rejected beside a valid REAL/stations1 report.
func TestT19StandInCannotCloseMatrix(t *testing.T) {
	real := t19ValidRealReport(t)
	if t19ReportExit(real) != 0 {
		t.Fatal("REAL stations1 positive control did not close")
	}
	standin := t19ValidReport(t)
	if standin.Items[4].Verdict != t19StandIn {
		t.Fatal("stand-in emitted as a wallet PASS")
	}
	if err := t19ValidateReport(standin); err != nil {
		t.Fatal("valid scoped stand-in report rejected:", err)
	}
	if code := t19ReportExit(standin); code != 2 {
		t.Fatalf("stand-in exit=%d, want scoped/non-closing exit 2", code)
	}
	b, err := os.ReadFile("testdata/t19-realhost/rev236-stand-in-pass.json")
	if err != nil {
		t.Fatal(err)
	}
	var plant t19RealHostReport
	if err = json.Unmarshal(b, &plant); err != nil {
		t.Fatal(err)
	}
	if plant.WalletKind != t19StandIn || plant.Items[4].Verdict != t19Pass {
		t.Fatal("reviewer regression fixture no longer plants stand-in-as-PASS")
	}
	if err := t19ValidateReport(plant); err == nil || err.Error() != "stand-in wallet cannot be reported as PASS" {
		t.Fatalf("reviewer fixture did not hit the intended stand-in rejection: %v", err)
	}
	if t19ReportExit(plant) == 0 {
		t.Fatal("reviewer's stand-in-as-PASS report closes")
	}
	encoded, err := json.Marshal(standin)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := t19DecodeReport(encoded)
	if err != nil || t19ReportExit(decoded) != 2 {
		t.Fatalf("stand-in schema roundtrip changed scoped verdict: %v", err)
	}
	real.Items[4].Verdict = t19StandIn
	if err := t19ValidateReport(real); err == nil || err.Error() != "real-wallet report contains stand-in evidence" {
		t.Fatalf("real report accepted stand-in item: %v", err)
	}
	real = t19ValidRealReport(t)
	for _, host := range []string{"rt-stations", "other-host"} {
		r := real
		r.Host = host
		if t19ReportExit(r) == 0 {
			t.Fatal("non-stations1 REAL report closed")
		}
	}
	for _, id := range []int{0, 7, 12} {
		r := t19ValidRealReport(t)
		r.Items[id].Verdict = t19StandIn
		if t19ReportExit(r) == 0 {
			t.Fatal("stand-in outside wallet item closed")
		}
	}
}
