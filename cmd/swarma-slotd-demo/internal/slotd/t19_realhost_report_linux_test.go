//go:build linux

package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"slices"
	"strconv"
	"strings"
)

const (
	t19HostedCommit  = "aed02d69d8e360567faf6bb9133c6b242613b2ef"
	t19HostedRun     = int64(43282197583)
	t19HostedJob     = int64(131406508394)
	t19HostedLogHash = "4fd39ebf14d35b280811e9924a8fdc79fc1402933d1e5ed390a1b04d06fc73ac"
	t19Pass          = "PASS"
	t19Fail          = "FAIL"
	t19StandIn       = "STAND_IN"
	t19Covered       = "COVERED_BY_HOSTED_ROOT_CI"
)

type t19Evidence struct {
	Claim    string   `json:"claim"`
	Observed any      `json:"observed,omitempty"`
	Problems []string `json:"problems,omitempty"`
}
type t19Item struct {
	HostedCommit string        `json:"hosted_commit"`
	HostedRunID  int64         `json:"hosted_run_id"`
	ID           string        `json:"id"`
	Verdict      string        `json:"verdict"`
	Evidence     []t19Evidence `json:"evidence"`
}
type t19CIEvidence struct {
	Commit    string `json:"commit"`
	RunID     int64  `json:"run_id"`
	JobID     int64  `json:"job_id"`
	LogSHA256 string `json:"log_sha256"`
	URL       string `json:"url"`
	Verified  bool   `json:"verified"`
	Error     string `json:"error,omitempty"`
}
type t19RealHostReport struct {
	RunID                  string        `json:"run_id,omitempty"`
	PropertyTemplateSHA256 string        `json:"property_template_sha256"`
	WalletKind             string        `json:"wallet_kind"`
	Restoration            t19Item       `json:"restoration"`
	Schema                 string        `json:"schema"`
	Host                   string        `json:"host"`
	Slot                   string        `json:"slot"`
	PolicySHA256           string        `json:"policy_sha256"`
	BinarySHA256           string        `json:"binary_sha256"`
	ProbeSHA256            string        `json:"probe_sha256"`
	Hosted                 t19CIEvidence `json:"hosted_root_ci"`
	Items                  []t19Item     `json:"items"`
	Controls               []t19Item     `json:"controls"`
	Cleanup                t19Item       `json:"cleanup"`
	Errors                 []string      `json:"errors,omitempty"`
}

var t19HostedTests = []string{
	"TestRootT19SlotConfinement/T19.6-wallet-restart", "TestRootT19LandlockFailClosed",
	"TestRootT19DetectorControl", "TestRootT19StatusSocketBound", "TestRootT19AlternateABI",
}

// A successful workflow alone is insufficient: mutant runs also succeed.
// Authenticate the exact audited full root log, its run/job identity and every
// named positive result. These immutable historical bytes are fetched by the
// operator using gh; no GitHub credentials are loaded by the root harness.
func t19VerifyHosted(run, jobs, log []byte) t19CIEvidence {
	return t19VerifyHostedLog(run, jobs, log, t19HostedLogHash)
}

func t19VerifyHostedLog(run, jobs, log []byte, expectedLogHash string) t19CIEvidence {
	ci := t19CIEvidence{Commit: t19HostedCommit, RunID: t19HostedRun, JobID: t19HostedJob,
		LogSHA256: digest(log), URL: fmt.Sprintf("https://github.com/relux-works/swarma-user-manager/actions/runs/%d", t19HostedRun)}
	refuse := func(s string) t19CIEvidence { ci.Error = s; return ci }
	var r struct {
		ID                       int64  `json:"id"`
		HeadSHA                  string `json:"head_sha"`
		Status, Conclusion, Path string
		RunAttempt               int `json:"run_attempt"`
		Repository               struct {
			FullName string `json:"full_name"`
		}
	}
	if json.Unmarshal(run, &r) != nil || r.ID != t19HostedRun || r.HeadSHA != t19HostedCommit || r.Status != "completed" || r.Conclusion != "success" || r.Path != ".github/workflows/slotd-demo.yml" || r.RunAttempt != 1 || r.Repository.FullName != "relux-works/swarma-user-manager" {
		return refuse("run identity/status differs from the audited hosted run")
	}
	var j struct {
		Jobs []struct {
			ID                       int64
			RunID                    int64  `json:"run_id"`
			HeadSHA                  string `json:"head_sha"`
			Name, Status, Conclusion string
			RunnerName               string `json:"runner_name"`
			Labels                   []string
		}
	}
	if json.Unmarshal(jobs, &j) != nil {
		return refuse("invalid jobs evidence")
	}
	found := false
	for _, job := range j.Jobs {
		if job.ID == t19HostedJob {
			found = job.RunID == t19HostedRun && job.HeadSHA == t19HostedCommit && job.Name == "root" && job.Status == "completed" && job.Conclusion == "success" && strings.HasPrefix(job.RunnerName, "GitHub Actions ") && slices.Contains(job.Labels, "ubuntu-26.04")
		}
	}
	if !found || ci.LogSHA256 != expectedLogHash {
		return refuse("root job or authenticated log differs from the audited full suite")
	}
	passed := map[string]bool{}
	for _, line := range bytes.Split(log, []byte("\n")) {
		at := bytes.Index(line, []byte(`{"Action":`))
		if at < 0 {
			continue
		}
		var e struct{ Action, Test string }
		if json.Unmarshal(line[at:], &e) != nil {
			return refuse("malformed root event")
		}
		if e.Action == "fail" || e.Action == "skip" {
			return refuse("root suite failed or skipped")
		}
		if e.Action == "pass" {
			passed[e.Test] = true
		}
	}
	for _, name := range t19HostedTests {
		if !passed[name] {
			return refuse("missing passing root test: " + name)
		}
	}
	if !bytes.Contains(log, []byte("root test pipeline status 0")) {
		return refuse("missing zero root exit")
	}
	ci.Verified = true
	return ci
}

func t19NewReport(host, slot string) t19RealHostReport {
	r := t19RealHostReport{Schema: "swarma.t19.realhost.v1", Host: host, Slot: slot, PropertyTemplateSHA256: digest(t19PropertyTemplate)}
	for i := 1; i <= 13; i++ {
		r.Items = append(r.Items, t19Item{HostedCommit: t19HostedCommit, HostedRunID: t19HostedRun, ID: fmt.Sprintf("T19.%d", i), Verdict: t19Fail, Evidence: []t19Evidence{{Claim: "observation not collected"}}})
	}
	for _, id := range []string{"detector-control", "bound-status-control", "alternate-ABI-control"} {
		r.Controls = append(r.Controls, t19Item{ID: id, Verdict: t19Fail, Evidence: []t19Evidence{{Claim: "hosted root control not verified"}}})
	}
	r.Restoration = t19Item{ID: "restoration", Verdict: t19Fail, Evidence: []t19Evidence{{Claim: "temporary policy removal, unchanged production readback and probe refusal not collected"}}}
	r.Cleanup = t19Item{ID: "cleanup", Verdict: t19Fail, Evidence: []t19Evidence{{Claim: "no retirement readback"}}}
	return r
}
func (r *t19RealHostReport) hostedItems() {
	v := t19Fail
	if r.Hosted.Verified {
		v = t19Covered
	}
	for _, id := range []int{6, 10} {
		r.Items[id-1] = t19Item{HostedCommit: t19HostedCommit, HostedRunID: t19HostedRun, ID: fmt.Sprintf("T19.%d", id), Verdict: v, Evidence: []t19Evidence{{Claim: "fixture/hook experiment; not executed on this host", Observed: r.Hosted}}}
	}
	for i := range r.Controls {
		r.Controls[i].Verdict = v
		r.Controls[i].Evidence = []t19Evidence{{Claim: "edited-unit or alternate-ABI control; not executed on this host", Observed: r.Hosted}}
	}
}
func t19Observation(id int, claim string, observed any, problems ...string) t19Item {
	v := t19Pass
	if len(problems) > 0 {
		v = t19Fail
	}
	return t19Item{HostedCommit: t19HostedCommit, HostedRunID: t19HostedRun, ID: fmt.Sprintf("T19.%d", id), Verdict: v, Evidence: []t19Evidence{{Claim: claim, Observed: observed, Problems: problems}}}
}

type t19HostFacts struct {
	WalletKind                     string
	WalletPeer                     t19PeerIdentity
	WalletPeerError                string
	ExpectedPeerUID                uint32
	ExpectedProperties             string
	Spec                           t19Spec
	Probe                          t19Report
	View                           t19ViewInventory
	Identity                       slotIdentity
	Plants                         []string
	AbstractPlant                  string
	HostAbstract                   map[string]string
	JournalFound                   bool
	UnitError, ExecError, NFTError string
	Properties                     map[string]string
	HostEcho                       string
}

// This observer and TestRootT19SlotConfinement read the same scalar table.
// Inventory is certified by the same two-walk classifier as the root suite.
func t19RealHostVerdicts(f t19HostFacts) []t19Item {
	expect := t19Expectations()
	r := t19NewReport("", "").Items
	got := f.Probe
	problems := []string{}
	require := func(ok bool, msg string) {
		if !ok {
			problems = append(problems, msg)
		}
	}
	finish := func(id int, claim string, obs any) {
		r[id-1] = t19Observation(id, claim, obs, problems...)
		problems = nil
	}
	reachable, issues := t19InventoryVerdict(f.View, got.Sockets, got.WalkErrors)
	problems = append(problems, issues...)
	require(slices.Equal(reachable, []string{t19WalletSock}) && slices.Equal(got.Sockets, []string{t19WalletSock}), "reachable socket inventory must be exactly wallet.sock")
	groups := groupSet(got.Groups)
	want := []int{int(f.Identity.UID), int(f.Identity.SocketGID)}
	slices.Sort(want)
	require(got.UID == int(f.Identity.UID) && got.GID == int(f.Identity.UID) && slices.Equal(groups, want), "slot UID/GID/groups differ from adopted policy")
	require(got.KeyRead == expect.KeyRead && got.KeyWrite == expect.KeyWrite && got.KeyChmod == expect.KeyChmod, "key read/write/chmod differs from read-only contract")
	finish(1, "complete mount-view inventory, adopted identity and read-only key", struct {
		Probe t19Report
		View  t19ViewInventory
	}{got, f.View})
	for _, path := range f.Spec.Pathnames {
		v := got.Pathnames[path]
		if path == t19WalletSock {
			require(v == expect.Connected, "wallet is not connectable")
		} else {
			require(slices.Contains(expect.PathDenied, v), fmt.Sprintf("%s: %s", path, v))
		}
	}
	finish(2, "every enumerated pathname socket refused except the wallet", got.Pathnames)
	live := 0
	for _, name := range f.Spec.Abstract {
		v := got.Abstract["@"+name]
		host := f.HostAbstract["@"+name]
		if host == expect.Connected {
			live++
			require(v == expect.Abstract, "abstract socket not scoped: "+name)
		} else {
			require(v != "" && v != expect.Connected, "missing or reachable abstract target: "+name)
		}
	}
	require(live > 0, "no connectable host abstract control")
	finish(3, "host-connectable abstract names get EPERM", struct{ Slot, Host map[string]string }{got.Abstract, f.HostAbstract})
	for _, path := range f.Plants {
		require(got.Pathnames[path] == expect.Hidden, "pathname plant visible: "+path)
	}
	require(got.Abstract["@"+f.AbstractPlant] == expect.Abstract, "abstract plant not scoped")
	finish(4, "owned pathname and abstract plants hidden", got.Pathnames)
	require(got.Pathnames[t19WalletSock] == expect.Connected, "wallet connect failed")
	require(f.WalletPeerError == "" && f.WalletPeer.PID > 0 && f.WalletPeer.UID == f.ExpectedPeerUID, "wallet peer identification failed or differs from operator pin")
	finish(5, f.WalletKind+": connect and kernel peer identification only; no wallet RPC or files", f.WalletPeer)
	if f.WalletKind == t19StandIn && r[4].Verdict == t19Pass {
		r[4].Verdict = t19StandIn
	}
	require(f.JournalFound, "probe stdout marker absent from unit journal")
	for _, p := range []string{"/run/systemd/journal/socket", "/dev/log"} {
		require(got.Pathnames[p] == expect.Hidden, "journald socket visible: "+p)
	}
	finish(7, "stdout reaches journal while direct journal sockets are hidden", f.JournalFound)
	for family, want := range expect.Families {
		require(got.Families[family] == want, "family verdict differs: "+family)
	}
	finish(8, "native address-family observations; alternate ABI is a hosted control", got.Families)
	require(got.Tamper["unshare-user-net"] != "" && got.Tamper["unshare-user-net"] != expect.Connected, "unshare did not refuse")
	for k, want := range expect.Tamper {
		require(got.Tamper[k] == want, "tamper verdict differs: "+k)
	}
	require(got.AfterTamper["@"+f.AbstractPlant] == expect.Abstract, "abstract reachable after tamper")
	for _, p := range f.Plants {
		require(got.AfterTamper[p] == expect.Hidden, "plant reachable after tamper: "+p)
	}
	for name, v := range got.AfterTamper {
		require(v != expect.Connected || name == t19WalletSock, "non-wallet reachable after tamper: "+name)
	}
	finish(9, "tampering restores no pathname or abstract access", struct{ Tamper, After map[string]string }{got.Tamper, got.AfterTamper})
	require(got.Pathnames[t19StatusSock] == expect.Hidden, "operator status socket visible")
	finish(11, "status absent; bound-on-purpose permission control is hosted only", got.Pathnames[t19StatusSock])
	for _, target := range f.Spec.IP[:max(0, len(f.Spec.IP)-1)] {
		key := target.Network + " " + target.Address
		want := expect.TCPDenied
		if strings.HasPrefix(target.Network, "udp") {
			want = expect.UDPDenied
		}
		require(got.IP[key] == want, "host-local verdict differs: "+key)
	}
	require(len(f.Spec.IP) >= 6, "missing required IP attempt set")
	require(f.HostEcho == expect.Connected, "host loopback echo positive control failed")
	finish(12, "loopback/host-RPC/resolver attempts denied, owned echo answers host", got.IP)
	gateway := t19Gateway(f.Spec)
	require(gateway.Address != "" && got.IP[gateway.Network+" "+gateway.Address] == expect.Connected, "allowed gateway not connectable")
	require(f.UnitError == "", "unit properties: "+f.UnitError)
	require(f.ExecError == "", "unit ExecStart: "+f.ExecError)
	require(f.NFTError == "", "nft readback: "+f.NFTError)
	finish(13, "policy-bound unit properties, ExecStart, exact NFT and allowed IP connection", struct {
		Expected   string
		Properties map[string]string
		IP         map[string]string
	}{f.ExpectedProperties, f.Properties, got.IP})
	return r
}

// The prepare path appends exactly one policy-approved TCP gateway last.
func t19Gateway(spec t19Spec) t19Target {
	if len(spec.IP) == 0 {
		return t19Target{}
	}
	return spec.IP[len(spec.IP)-1]
}

func t19ValidateReport(r t19RealHostReport) error {
	if r.PropertyTemplateSHA256 != digest(t19PropertyTemplate) {
		return errors.New("property template hash mismatch")
	}
	if r.Schema != "swarma.t19.realhost.v1" || r.Host == "" || !slotPattern.MatchString(r.Slot) || len(r.Items) != 13 || len(r.Controls) != 3 {
		return errors.New("invalid report header/cardinality")
	}
	for _, hash := range []string{r.PolicySHA256, r.BinarySHA256, r.ProbeSHA256} {
		if !digestPattern.MatchString(hash) && !(hash == "" && len(r.Errors) > 0) {
			return errors.New("missing artifact hash")
		}
	}
	for i, it := range r.Items {
		if it.HostedCommit != t19HostedCommit || it.HostedRunID != t19HostedRun || it.ID != "T19."+strconv.Itoa(i+1) || len(it.Evidence) == 0 {
			return errors.New("missing, reordered or duplicate T19 item")
		}
		if err := t19ValidateVerdict(it, r.Hosted, i == 5 || i == 9); err != nil {
			return err
		}
	}
	for i, id := range []string{"detector-control", "bound-status-control", "alternate-ABI-control"} {
		if r.Controls[i].ID != id {
			return errors.New("invalid control inventory")
		}
		if err := t19ValidateVerdict(r.Controls[i], r.Hosted, true); err != nil {
			return err
		}
	}
	if r.Cleanup.ID != "cleanup" {
		return errors.New("cleanup evidence absent")
	}
	if err := t19ValidateVerdict(r.Restoration, r.Hosted, false); err != nil {
		return err
	}
	if r.Restoration.ID != "restoration" {
		return errors.New("restoration evidence absent")
	}
	if r.WalletKind != "REAL" && r.WalletKind != "STAND_IN" {
		return errors.New("wallet kind absent")
	}
	if r.Host == "rt-stations" && r.WalletKind != "STAND_IN" {
		return errors.New("rt-stations wallet is a stand-in")
	}
	if r.Host == "stations1" && r.WalletKind != "REAL" {
		return errors.New("stations1 requires a real-wallet observation")
	}
	if r.WalletKind == t19StandIn && r.Items[4].Verdict == t19Pass {
		return errors.New("stand-in wallet cannot be reported as PASS")
	}
	if r.WalletKind == "REAL" && r.Items[4].Verdict == t19StandIn {
		return errors.New("real-wallet report contains stand-in evidence")
	}
	if !t19RunIDValid(r.RunID) && len(r.Errors) == 0 {
		return errors.New("report lacks a fresh run identity")
	}
	return t19ValidateVerdict(r.Cleanup, r.Hosted, false)
}
func t19ValidateVerdict(it t19Item, ci t19CIEvidence, hosted bool) error {
	if len(it.Evidence) == 0 {
		return errors.New("empty evidence")
	}
	for _, e := range it.Evidence {
		if e.Claim == "" || ((it.Verdict == t19Pass || it.Verdict == t19StandIn) && len(e.Problems) > 0) {
			return errors.New("inconsistent evidence")
		}
	}
	switch it.Verdict {
	case t19Pass:
		if hosted {
			return errors.New("hosted-only experiment cannot be PASS")
		}
	case t19Covered:
		if !hosted || !ci.Verified || ci.Commit != t19HostedCommit || ci.RunID != t19HostedRun || ci.JobID != t19HostedJob || ci.LogSHA256 != t19HostedLogHash || ci.Error != "" {
			return errors.New("unverified hosted coverage")
		}
	case t19StandIn:
		if hosted || it.ID != "T19.5" {
			return errors.New("stand-in verdict is only valid for the observed wallet item")
		}
	case t19Fail:
	default:
		return errors.New("unknown verdict")
	}
	return nil
}
func t19ReportExit(r t19RealHostReport) int {
	if t19ValidateReport(r) != nil || len(r.Errors) > 0 || r.Cleanup.Verdict != t19Pass || r.Restoration.Verdict != t19Pass {
		return 1
	}
	for _, it := range append(slices.Clone(r.Items), r.Controls...) {
		if it.Verdict != t19Pass && it.Verdict != t19Covered && it.Verdict != t19StandIn {
			return 1
		}
	}
	// Exit 2 is an explicitly scoped stand-in observation, never matrix closure.
	if r.WalletKind == t19StandIn {
		return 2
	}
	if r.Host != "stations1" || r.WalletKind != "REAL" {
		return 1
	}

	return 0
}

func t19DecodeReport(b []byte) (t19RealHostReport, error) {
	var r t19RealHostReport
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("extra report document")
	}
	return r, t19ValidateReport(r)
}

// Read-only evidence verification is available without root/host admission so
// the install bench can authenticate the archived run before opening a window.
func runT19CICheck(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: slotd-t19-ci-check DIRECTORY")
		return 2
	}
	var inputs [][]byte
	for _, name := range []string{"root-run.json", "root-jobs.json", "root-job.log"} {
		path := filepath.Join(args[0], name)
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hosted evidence unavailable:", name)
			return 1
		}
		f := os.NewFile(uintptr(fd), path)
		st, err := fdStat(f)
		if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 8*1024*1024 {
			f.Close()
			fmt.Fprintln(os.Stderr, "hosted evidence metadata refused:", name)
			return 1
		}
		b, err := readBounded(f, 8*1024*1024)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "hosted evidence read failed:", name)
			return 1
		}
		inputs = append(inputs, b)
	}
	ci := t19VerifyHosted(inputs[0], inputs[1], inputs[2])
	b, err := json.MarshalIndent(ci, "", "  ")
	if err != nil {
		return 1
	}
	fmt.Println(string(b))
	if !ci.Verified {
		return 1
	}
	return 0
}
