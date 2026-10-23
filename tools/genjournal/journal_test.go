package genjournal

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
	"strings"
	"syscall"
	"testing"
	"time"
)

var genesis = Floor{0, ZeroHash}

const token = "11111111111111111111111111111111"

func code(e error) string {
	if e == nil {
		return "ok"
	}
	var r *Refusal
	if errors.As(e, &r) {
		return r.Code
	}
	return e.Error()
}
func wantCode(t *testing.T, e error, want string) {
	t.Helper()
	if got := code(e); got != want {
		t.Fatalf("got %s, want %s (%v)", got, want, e)
	}
}
func vector(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("../../vectors/gen-journal", name+".jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fixture(t *testing.T, b []byte) (string, policy) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	p := policy{uint32(os.Getuid()), anchor}
	dir := filepath.Join(anchor, "generations")
	if e := initialize(dir, p); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "journal"), b, 0644); e != nil {
		t.Fatal(e)
	}
	return dir, p
}

type vectorCase struct {
	Name, File, Expect, Control string
	Floor                       *Floor
	Fixture                     *struct{ Target, Violation string }
}

func loadCases(t *testing.T) []vectorCase {
	t.Helper()
	b, e := os.ReadFile("../../vectors/gen-journal/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var m struct {
		Format string
		Cases  []vectorCase
	}
	if e = json.Unmarshal(b, &m); e != nil || m.Format != "gen-journal-vectors/1" {
		t.Fatalf("manifest: %v", e)
	}
	return m.Cases
}
func checkCase(t *testing.T, c vectorCase) error {
	t.Helper()
	floor := genesis
	if c.Floor != nil {
		floor = *c.Floor
	}
	if c.Fixture == nil {
		b, e := os.ReadFile(filepath.Join("../../vectors/gen-journal", c.File))
		if e != nil {
			t.Fatal(e)
		}
		_, e = Verify(bytes.NewReader(b), floor)
		return e
	}
	dir, p := fixture(t, vector(t, "active"))
	_, positiveErr := inspect(context.Background(), dir, genesis, p)
	wantCode(t, positiveErr, "ok")
	f := c.Fixture
	path := filepath.Join(dir, f.Target)

	if f.Target == "writer.pending" && f.Violation != "present" {
		if e := makeIntent(dir, p); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		m, e := decodePending(b)
		if e != nil {
			t.Fatal(e)
		}
		switch f.Violation {
		case "empty":
			b = nil
		case "malformed":
			b = []byte("unexpected state")
		case "noncanonical":
			b = append([]byte(" "), b...)
		case "bad-budget":
			b = bytes.Replace(b, []byte(`"budget_ms":1000`), []byte(`"budget_ms":999`), 1)
		case "duplicate-field":
			b = append(append([]byte{}, b[:len(b)-2]...), []byte(`,"budget_ms":1000}`+"\n")...)
		case "oversized":
			b = bytes.Repeat([]byte{'x'}, MaxPending+1)
		case "stale":
			m.StartedMS -= 2000
			b, e = encodePending(m)
		case "other-boot":
			m.BootID = "00000000-0000-0000-0000-000000000000"
			b, e = encodePending(m)
		case "future-start":
			m.StartedMS += 10000
			b, e = encodePending(m)
		default:
			t.Fatal("unknown pending fixture")
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0644); e != nil {
			t.Fatal(e)
		}
		_, e = inspect(context.Background(), dir, floor, p)
		return e
	}
	switch f.Violation {
	case "owner":
		// Non-root fixtures test expected-owner mismatch directly; no chown or root is needed.
		if f.Target == "directory" {
			path = dir
		}
		file, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		defer file.Close()
		mode := uint32(0644)
		if f.Target == "directory" {
			mode = 0755
		}
		return statOK(file, p.owner+1, mode, f.Target == "directory")
	case "mode":
		if f.Target == "directory" {
			path = dir
		}
		if f.Target == "ancestor" {
			path = p.anchor
		}
		if e := os.Chmod(path, 0777); e != nil {
			t.Fatal(e)
		}
	case "symlink":
		if f.Target == "directory" {
			path = dir
		}
		if f.Target == "ancestor" {
			actual := p.anchor
			link := filepath.Join(actual, "link")
			if e := os.Symlink(dir, link); e != nil {
				t.Fatal(e)
			}
			dir = filepath.Join(link, "child")
		} else {
			renamed := path + ".real"
			if e := os.Rename(path, renamed); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink(renamed, path); e != nil {
				t.Fatal(e)
			}
		}
	case "missing":
		if e := os.Remove(path); e != nil {
			t.Fatal(e)
		}
	case "hardlink":
		if e := os.Link(path, path+".link"); e != nil {
			t.Fatal(e)
		}
	case "present":
		if e := makeIntent(dir, p); e != nil {
			t.Fatal(e)
		}
	case "file-size":
		file, e := os.OpenFile(path, os.O_WRONLY, 0)
		if e != nil {
			t.Fatal(e)
		}
		e = file.Truncate(MaxFile + 1)
		file.Close()
		if e != nil {
			t.Fatal(e)
		}
	default:
		t.Fatalf("unknown fixture %s", f.Violation)
	}
	_, e := inspect(context.Background(), dir, floor, p)
	return e
}

// TestVectors proves every stable vector verdict and its named nearest valid control.
func TestVectors(t *testing.T) {
	cases := loadCases(t)
	byName := map[string]vectorCase{}
	for _, c := range cases {
		if _, ok := byName[c.Name]; ok {
			t.Fatal("duplicate vector name")
		}
		byName[c.Name] = c
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Expect != "ok" {
				control, ok := byName[c.Control]
				if !ok || control.Expect != "ok" {
					t.Fatal("missing positive control")
				}
				wantCode(t, checkCase(t, control), "ok")
			}
			wantCode(t, checkCase(t, c), c.Expect)
		})
	}
}

// TestBrokenChainPlant proves the validator rejects a corrupted link after a valid positive control.
func TestBrokenChainPlant(t *testing.T) {
	_, e := Verify(bytes.NewReader(vector(t, "active")), genesis)
	wantCode(t, e, "ok")
	_, e = Verify(bytes.NewReader(vector(t, "broken-chain")), genesis)
	wantCode(t, e, "journal_chain")
}

// TestActiveView proves only the exact active incarnation admits; missing, retired and recycled identities refuse.
func TestActiveView(t *testing.T) {
	for _, name := range []string{"active", "retiring", "removed", "recycle"} {
		v, e := Verify(bytes.NewReader(vector(t, name)), genesis)
		wantCode(t, e, "ok")
		want := "generation_inactive"
		if name == "active" {
			want = "ok"
		}
		if name == "recycle" {
			want = "generation_mismatch"
		}
		wantCode(t, v.Active(30001, token), want)
		wantCode(t, v.Active(30002, token), "generation_missing")
	}
}

// TestParserBoundaries proves schema types, encoding and floor bounds refuse before admission.
func TestParserBoundaries(t *testing.T) {
	valid := vector(t, "creating")
	for _, tc := range []struct {
		name  string
		b     []byte
		floor Floor
		want  string
	}{
		{"invalid-floor", valid, Floor{-1, ZeroHash}, "journal_floor"},
		{"zero-floor-hash", valid, Floor{0, strings.Repeat("a", 64)}, "journal_floor"},
		{"array", []byte("[]\n"), genesis, "journal_fields"},
		{"invalid-utf8", append([]byte{255}, '\n'), genesis, "journal_json"},
		{"numeric-overflow", bytes.Replace(valid, []byte(`"seq":1`), []byte(`"seq":9007199254740992`), 1), genesis, "journal_json"},
		{"null-state", bytes.Replace(valid, []byte(`"state":"creating"`), []byte(`"state":null`), 1), genesis, "journal_state"},
		{"wrong-prev-type", bytes.Replace(valid, []byte(`"prev":"`+ZeroHash+`"`), []byte(`"prev":null`), 1), genesis, "journal_prev"},
	} {
		t.Run(tc.name, func(t *testing.T) { _, e := Verify(bytes.NewReader(tc.b), tc.floor); wantCode(t, e, tc.want) })
	}
}

// TestReadFailure proves a failed read cannot become an empty valid journal.
func TestReadFailure(t *testing.T) {
	_, e := Verify(failingReader{}, genesis)
	wantCode(t, e, "journal_io")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func testTool(t *testing.T, p policy) string {
	t.Helper()
	bin, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	tool := filepath.Join(p.anchor, "checker")
	// Single-quote escaping is used only for this locally generated test launcher.
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	body := "#!/bin/sh\nexec " + quote(bin) + " -test.run='^TestRunbookTool$' -- \"$@\"\n"
	if e = os.WriteFile(tool, []byte(body), 0755); e != nil {
		t.Fatal(e)
	}
	return tool
}

// TestRunbookTool is a test-binary-only owner override; production CLI never reads these variables.
func TestRunbookTool(t *testing.T) {
	if os.Getenv("GEN_JOURNAL_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			os.Exit(run(args[i+1:], os.Stdout, os.Stderr, policy{uint32(os.Getuid()), os.Getenv("GEN_JOURNAL_TEST_ANCHOR")}))
		}
	}
	os.Exit(2)
}
func runbook(t *testing.T, tool string, p policy, args ...string) (string, error) {
	t.Helper()
	script, e := filepath.Abs("../manual-journal.sh")
	if e != nil {
		t.Fatal(e)
	}
	command := exec.Command("sh", append([]string{script, tool}, args...)...)
	command.Env = append(os.Environ(), "GEN_JOURNAL_TEST_HELPER=1", "GEN_JOURNAL_TEST_ANCHOR="+p.anchor)
	b, e := command.CombinedOutput()
	return string(b), e
}
func manualAppend(t *testing.T, tool, dir string, p policy, state, gen string) (string, error) {
	t.Helper()
	return runbook(t, tool, p, "append", dir, "0", ZeroHash, "30000", "59999", "30001", gen, state, "2026-10-01T00:00:00Z")
}

// TestManualRunbook proves documented init, lifecycle/recycle and explicit recovery; invalid input never appends.
func TestManualRunbook(t *testing.T) {
	anchor := t.TempDir()
	os.Chmod(anchor, 0755)
	p := policy{uint32(os.Getuid()), anchor}
	dir := filepath.Join(anchor, "generations")
	tool := testTool(t, p)
	if out, e := runbook(t, tool, p, "init", dir); e != nil {
		t.Fatalf("init: %v %s", e, out)
	}
	for _, s := range []string{"creating", "active", "retiring", "removed"} {
		if out, e := manualAppend(t, tool, dir, p, s, token); e != nil {
			t.Fatalf("%s: %v %s", s, e, out)
		}
	}
	next := strings.Repeat("2", 32)
	for _, s := range []string{"creating", "active"} {
		if out, e := manualAppend(t, tool, dir, p, s, next); e != nil {
			t.Fatalf("recycle: %v %s", e, out)
		}
	}
	before, e := os.ReadFile(filepath.Join(dir, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	if out, e := manualAppend(t, tool, dir, p, "removed", next); e == nil || !strings.Contains(out, "journal_transition") {
		t.Fatalf("forbidden direct removal: %v %s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("rejected transition changed journal")
	}
	_, e = inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "journal_writer_pending")
	if out, e := runbook(t, tool, p, "reconcile", dir, "0", ZeroHash); e != nil {
		t.Fatalf("reviewed reconciliation: %v %s", e, out)
	}
	// Each invalid input has a nearby successful lifecycle control above and leaves only a safety fence.
	invalid := [][]string{
		{"0", ZeroHash, "30000", "59999", "29999", token, "creating", "2026-10-01T00:00:00Z"},
		{"0", ZeroHash, "30000", "59999", "30001", "UPPERCASE", "retiring", "2026-10-01T00:00:00Z"},
		{"0", ZeroHash, "30000", "59999", "30001", next, "retiring", "bad-time"},
	}
	for i, a := range invalid {
		out, e := runbook(t, tool, p, append([]string{"append", dir}, a...)...)
		if e == nil || !strings.Contains(out, []string{"journal_station_range", "journal_generation", "journal_time"}[i]) {
			t.Fatalf("invalid input wrong refusal: %v %s", e, out)
		}
		now, _ := os.ReadFile(filepath.Join(dir, "journal"))
		if !bytes.Equal(before, now) {
			t.Fatal("invalid input appended")
		}
		if out, e = runbook(t, tool, p, "reconcile", dir, "0", ZeroHash); e != nil {
			t.Fatalf("recover: %v %s", e, out)
		}
	}
	v, e := inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "ok")
	wantCode(t, v.Active(30001, next), "ok")
}

// TestManualGuards proves set -e stops after an injected checker failure and never clears its fence.
func TestManualGuards(t *testing.T) {
	for _, phase := range []string{"intent", "lock-writer", "append-locked", "finish-intent"} {
		t.Run(phase, func(t *testing.T) {
			dir, p := fixture(t, vector(t, "active"))
			real := testTool(t, p)
			log := filepath.Join(p.anchor, "calls")
			wrapper := filepath.Join(p.anchor, "failing-checker")
			body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$1\" >> '%s'\nif [ \"$1\" = '%s' ]; then exit 23; fi\nexec '%s' \"$@\"\n", log, phase, real)
			if e := os.WriteFile(wrapper, []byte(body), 0755); e != nil {
				t.Fatal(e)
			}
			_, e := manualAppend(t, wrapper, dir, p, "retiring", token)
			if e == nil {
				t.Fatal("guard failed open")
			}
			calls, _ := os.ReadFile(log)
			stages := strings.Fields(string(calls))
			if len(stages) == 0 || stages[len(stages)-1] != phase {
				t.Fatalf("continued past failure: %s", calls)
			}
			if phase != "intent" {
				_, e = inspect(context.Background(), dir, genesis, p)
				wantCode(t, e, "journal_writer_pending")
			}
		})
	}
}

// TestGenesisRefusal proves initialization never replaces an existing journal or lock inode.
func TestGenesisRefusal(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	wantCode(t, initialize(dir, p), "journal_create")
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("genesis replaced evidence")
	}
}

// TestReleaseWins proves retirement cannot append in the middle of a data-locked durable release.
func TestReleaseWins(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	inside := make(chan struct{})
	release := make(chan struct{})
	readDone := make(chan error, 1)
	go func() {
		readDone <- withActive(context.Background(), dir, genesis, 30001, token, p, func(v View, deadline time.Time) error {
			close(inside)
			<-release
			if time.Now().After(deadline) {
				return refuse("journal_reader_deadline")
			}
			audit, e := os.OpenFile(filepath.Join(p.anchor, "durable-result"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			if _, e = audit.Write([]byte("result committed")); e != nil {
				audit.Close()
				return e
			}
			e = audit.Sync()
			audit.Close()
			if e != nil {
				return e
			}
			if time.Now().After(deadline) {
				return refuse("journal_reader_deadline")
			}
			return os.WriteFile(filepath.Join(p.anchor, "released"), []byte("issued"), 0600)
		})
	}()
	<-inside
	writerDone := make(chan error, 1)
	go func() {
		out, e := manualAppend(t, tool, dir, p, "retiring", token)
		if e != nil {
			e = fmt.Errorf("%w: %s", e, out)
		}
		writerDone <- e
	}()
	waitPending(t, dir)
	b, _ := os.ReadFile(filepath.Join(dir, "journal"))
	v, e := Verify(bytes.NewReader(b), genesis)
	wantCode(t, e, "ok")
	wantCode(t, v.Active(30001, token), "ok")
	close(release)
	wantCode(t, <-readDone, "ok")
	if e := <-writerDone; e != nil {
		t.Fatal(e)
	}
	v, e = inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "ok")
	wantCode(t, v.Active(30001, token), "generation_inactive")
	if _, e = os.Stat(filepath.Join(p.anchor, "released")); e != nil {
		t.Fatal("winning release not issued")
	}
}

// TestRetirementWins proves a signature computed remotely before retirement is discarded at final revalidation.
func TestRetirementWins(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	// Remote computation happens before entering the window; no generation lock is held here.
	computed := true
	if out, e := manualAppend(t, tool, dir, p, "retiring", token); e != nil {
		t.Fatalf("writer: %v %s", e, out)
	}
	released := false
	e := withActive(context.Background(), dir, genesis, 30001, token, p, func(View, time.Time) error { released = computed; return nil })
	wantCode(t, e, "generation_inactive")
	if released {
		t.Fatal("retirement lost the fence")
	}
}
func waitPending(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(filepath.Join(dir, "writer.pending")); e == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("writer did not publish intent")
}

// TestWriterProgress proves new signing traffic refuses while a fenced writer waits for an existing reader.
func TestWriterProgress(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	data, e := os.Open(filepath.Join(dir, "data.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer data.Close()
	if e = syscall.Flock(int(data.Fd()), syscall.LOCK_SH); e != nil {
		t.Fatal(e)
	}
	defer unlock(data)
	result := make(chan error, 1)
	go func() {
		out, e := manualAppend(t, tool, dir, p, "retiring", token)
		if e != nil {
			e = fmt.Errorf("%w: %s", e, out)
		}
		result <- e
	}()
	waitPending(t, dir)
	for i := 0; i < 100; i++ {
		_, e := inspect(context.Background(), dir, genesis, p)
		wantCode(t, e, "journal_writer_pending")
	}
	unlock(data)
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writer starved after reader drained")
	}
}

// TestWriterTimeout proves a stalled data holder prevents append and leaves a durable closed-admission marker.
func TestWriterTimeout(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	data, e := os.Open(filepath.Join(dir, "data.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer data.Close()
	if e = syscall.Flock(int(data.Fd()), syscall.LOCK_SH); e != nil {
		t.Fatal(e)
	}
	defer unlock(data)
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	out, e := manualAppend(t, tool, dir, p, "retiring", token)
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 1 || !strings.Contains(out, "journal_writer_deadline") {
		t.Fatalf("writer did not hit the whole-operation deadline: %v %s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("timeout appended")
	}
	_, e = inspect(context.Background(), dir, genesis, p)
	if got := code(e); got != "journal_writer_pending" && got != "journal_writer_stale" {
		t.Fatalf("timeout did not keep admission closed: %v", e)
	}
}

// TestReaderCancellation proves a cancelled caller cannot enter its release callback.
func TestReaderCancellation(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := withActive(ctx, dir, genesis, 30001, token, p, func(View, time.Time) error { t.Fatal("cancelled window released"); return nil })
	wantCode(t, e, "journal_lock_timeout")
}

// TestProductionOwnerCannotBeRelaxed proves the shipped CLI has no expected-owner option or test environment override.
func TestProductionOwnerCannotBeRelaxed(t *testing.T) {
	dir, _ := fixture(t, vector(t, "active"))
	var out, err bytes.Buffer
	exit := Run([]string{"verify", dir, "0", ZeroHash, "--expected-owner", strconv.Itoa(os.Getuid())}, &out, &err)
	if exit != 2 || out.Len() != 0 {
		t.Fatalf("owner override accepted: %d %s", exit, out.String())
	}
	if os.Getuid() != 0 {
		f, e := os.Open(filepath.Join(dir, "journal"))
		if e != nil {
			t.Fatal(e)
		}
		defer f.Close()
		wantCode(t, statOK(f, 0, 0644, false), "journal_owner")
	}
}

// TestGenesisRollback proves an unused genesis can be removed while any recorded history is preserved.
func TestGenesisRollback(t *testing.T) {
	for _, used := range []bool{false, true} {
		t.Run(strconv.FormatBool(used), func(t *testing.T) {
			data := []byte{}
			if used {
				data = vector(t, "creating")
			}
			dir, p := fixture(t, data)
			tool := testTool(t, p)
			out, e := runbook(t, tool, p, "rollback-genesis", dir)
			if used {
				if e == nil || !strings.Contains(out, "journal_genesis_in_use") {
					t.Fatalf("used genesis removed: %v %s", e, out)
				}
				after, _ := os.ReadFile(filepath.Join(dir, "journal"))
				if !bytes.Equal(data, after) {
					t.Fatal("used history altered")
				}
			} else {
				if e != nil {
					t.Fatalf("rollback: %v %s", e, out)
				}
				if _, e = os.Stat(dir); !os.IsNotExist(e) {
					t.Fatalf("unused genesis remains: %v", e)
				}
			}
		})
	}
}

// TestReadBudget proves an already expired validation window returns no usable view.
func TestReadBudget(t *testing.T) {
	_, e := verifyUntil(bytes.NewReader(vector(t, "active")), genesis, time.Now().Add(-time.Second))
	wantCode(t, e, "journal_reader_deadline")
}

// TestOfflineCLI proves raw-file views and exact refusal output work without protected production paths.
func TestOfflineCLI(t *testing.T) {
	for _, name := range []string{"active", "broken-chain"} {
		var out, errs bytes.Buffer
		exit := Run([]string{"bytes", "../../vectors/gen-journal/" + name + ".jsonl", "0", ZeroHash}, &out, &errs)
		if name == "active" {
			if exit != 0 || errs.Len() != 0 || !strings.Contains(out.String(), `"state":"active"`) {
				t.Fatalf("valid CLI: %d %s %s", exit, &out, &errs)
			}
		} else {
			if exit != 1 || out.Len() != 0 || errs.String() != "{\"Code\":\"journal_chain\",\"Line\":2}\n" {
				t.Fatalf("invalid CLI: %d %s %s", exit, &out, &errs)
			}
		}
	}
}

// TestRunbookMarker proves the executable runbook tested above is the one linked by the specification.
func TestRunbookMarker(t *testing.T) {
	b, e := os.ReadFile("../../spec/generation-journal.md")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte("<!-- runbook-check: tools/manual-journal.sh -->")) {
		t.Fatal("runbook marker missing")
	}
}

// TestMissingLockCannotBeCreated proves the manual writer refuses a missing lock without creating it or changing history.
func TestMissingLockCannotBeCreated(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	path := filepath.Join(dir, "gate.lock")
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	out, e := manualAppend(t, tool, dir, p, "retiring", token)
	if e == nil || !strings.Contains(out, "journal_missing") {
		t.Fatalf("missing lock accepted: %v %s", e, out)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("writer created lock")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(after, vector(t, "active")) {
		t.Fatal("missing lock changed history")
	}
}

// TestReconcileRejectsFork proves reconciliation cannot lower a floor or clear admission over conflicting history.
func TestReconcileRejectsFork(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	tool := testTool(t, p)
	if e := makeIntent(dir, p); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	out, e := runbook(t, tool, p, "reconcile", dir, "2", strings.Repeat("f", 64))
	if e == nil || !strings.Contains(out, "journal_fork") {
		t.Fatalf("fork reconciled: %v %s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("reconcile changed journal")
	}
	_, e = inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "journal_writer_pending")
}

// TestAppendNeedsVerifiedLocks proves a direct record helper cannot mutate the journal outside the lock protocol.
func TestAppendNeedsVerifiedLocks(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	if e := makeIntent(dir, p); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	e := appendRecord(dir, genesis, 30000, 59999, 30001, token, "retiring", "2026-10-01T00:00:00Z", p)
	wantCode(t, e, "journal_lock")
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(before, after) {
		t.Fatal("unlocked helper appended")
	}
}

// TestGenesisPathGuard proves a non-normalized path is rejected before creating any directory.
func TestGenesisPathGuard(t *testing.T) {
	anchor := t.TempDir()
	os.Chmod(anchor, 0755)
	p := policy{uint32(os.Getuid()), anchor}
	path := anchor + "/unused/../generations"
	wantCode(t, initialize(path, p), "journal_path")
	entries, e := os.ReadDir(anchor)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 0 {
		t.Fatal("invalid genesis path mutated parent")
	}
}
