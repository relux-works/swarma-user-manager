package genjournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMalformedFenceReconcile proves invalid marker bytes survive refused reconciliation; the writer-generated marker is the positive neighbor.
func TestMalformedFenceReconcile(t *testing.T) {
	for _, bad := range []string{"valid", "unexpected state", "", "{}\n"} {
		t.Run(fmt.Sprintf("marker-%q", bad), func(t *testing.T) {
			dir, p := fixture(t, vector(t, "active"))
			tool := testTool(t, p)
			if e := makeIntent(dir, p); e != nil {
				t.Fatal(e)
			}
			marker := filepath.Join(dir, "writer.pending")
			before, _ := os.ReadFile(filepath.Join(dir, "journal"))
			if bad != "valid" {
				if e := os.WriteFile(marker, []byte(bad), 0644); e != nil {
					t.Fatal(e)
				}
			}
			out, e := runbook(t, tool, p, "reconcile", dir, "0", ZeroHash)
			if bad == "valid" {
				if e != nil {
					t.Fatalf("valid marker refused: %v %s", e, out)
				}
				_, e = inspect(context.Background(), dir, genesis, p)
				wantCode(t, e, "ok")
				return
			}
			if e == nil || !strings.Contains(out, "journal_pending_malformed") {
				t.Fatalf("malformed marker reconciled or wrong refusal: %v %s", e, out)
			}
			after, _ := os.ReadFile(filepath.Join(dir, "journal"))
			kept, readErr := os.ReadFile(marker)
			if readErr != nil || !bytes.Equal(kept, []byte(bad)) || !bytes.Equal(before, after) {
				t.Fatal("reconciliation changed malformed evidence or journal")
			}
			_, e = inspect(context.Background(), dir, genesis, p)
			wantCode(t, e, "journal_pending_malformed")
		})
	}
}

// TestExpiredWriterBudget proves an expired valid fence prevents append and remains for reconciliation.
func TestExpiredWriterBudget(t *testing.T) {
	dir, p := fixture(t, vector(t, "active"))
	real := testTool(t, p)
	wrapper := filepath.Join(p.anchor, "expired-checker")
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	old := fmt.Sprintf("{\"boot_id\":\"%s\",\"budget_ms\":1000,\"format\":\"gen-journal-pending/1\",\"started_ms\":0}\n", strings.TrimSpace(string(boot)))
	marker := filepath.Join(dir, "writer.pending")
	body := fmt.Sprintf("#!/bin/sh\nset -eu\n'%s' \"$@\"\nif [ \"$1\" = intent ]; then\nprintf '%%s' '%s' > '%s'\nfi\n", real, old, marker)
	if e = os.WriteFile(wrapper, []byte(body), 0755); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "journal"))
	out, e := manualAppend(t, wrapper, dir, p, "retiring", token)
	if e == nil || !strings.Contains(out, "journal_writer_deadline") {
		t.Fatalf("expired writer appended or wrong refusal: %v %s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	kept, _ := os.ReadFile(marker)
	if !bytes.Equal(before, after) || !bytes.Equal(kept, []byte(old)) {
		t.Fatal("expired writer altered journal or marker")
	}
}

// TestJournalFileLimit proves the published 1 MiB ceiling rejects excess bytes before interpreting any line.
func TestJournalFileLimit(t *testing.T) {
	_, e := Verify(bytes.NewReader(bytes.Repeat([]byte{' '}, 1048577)), genesis)
	wantCode(t, e, "journal_file_size")
}

// TestPendingGateWindow proves intent published after the first check prevents release at the second check; the unfenced neighbor releases.
func TestPendingGateWindow(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(fmt.Sprint(fenced), func(t *testing.T) {
			dir, p := fixture(t, vector(t, "active"))
			crossed, called := false, false
			hook := func() {
				crossed = true
				if fenced {
					if e := makeIntent(dir, p); e != nil {
						t.Fatal(e)
					}
				}
			}
			e := readWindowAtBoundary(context.Background(), dir, p, hook, func(_ *directory, j *os.File, deadline time.Time) error {
				v, e := verifyUntil(j, genesis, deadline)
				if e != nil {
					return e
				}
				if e = v.Active(30001, token); e != nil {
					return e
				}
				called = true
				return nil
			})
			want := "ok"
			if fenced {
				want = "journal_writer_pending"
			}
			wantCode(t, e, want)
			if !crossed || called == fenced {
				t.Fatalf("boundary crossed=%v release=%v fenced=%v", crossed, called, fenced)
			}
		})
	}
}

// TestPendingRetryClassification proves clock/boot/age influence retry advice only; every present valid marker refuses admission.
func TestPendingRetryClassification(t *testing.T) {
	m := pendingRecord{"11111111-1111-1111-1111-111111111111", 100, WriterBudgetMS}
	for _, tc := range []struct {
		name, boot string
		now        int64
		clockErr   error
		want       string
	}{
		{"fresh", m.BootID, 100, nil, "journal_writer_pending"},
		{"slow-within-margin", m.BootID, 1599, nil, "journal_writer_pending"},
		{"stale-boundary", m.BootID, 1600, nil, "journal_writer_stale"},
		{"other-boot", "22222222-2222-2222-2222-222222222222", 100, nil, "journal_writer_stale"},
		{"future-start", m.BootID, 99, nil, "journal_writer_stale"},
		{"clock-unavailable", m.BootID, 100, refuse("journal_clock"), "journal_writer_stale"},
	} {
		t.Run(tc.name, func(t *testing.T) { wantCode(t, classifyPending(m, tc.boot, tc.now, tc.clockErr), tc.want) })
	}
	dir, p := fixture(t, vector(t, "active"))
	if e := makeIntent(dir, p); e != nil {
		t.Fatal(e)
	}
	_, e := inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "journal_writer_pending")
	boot, now, e := bootEvidence()
	if e != nil {
		t.Fatal(e)
	}
	b, e := encodePending(pendingRecord{boot, now - 2000, WriterBudgetMS})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "writer.pending"), b, 0644); e != nil {
		t.Fatal(e)
	}
	_, e = inspect(context.Background(), dir, genesis, p)
	wantCode(t, e, "journal_writer_stale")
	// Stale is advice to the operator; it is never permission to clear the marker automatically.
	kept, e := os.ReadFile(filepath.Join(dir, "writer.pending"))
	if e != nil || !bytes.Equal(kept, b) {
		t.Fatal("stale observation changed marker")
	}
}

// TestPendingSchema proves the closed canonical marker parser rejects malformed neighbors, including legacy empty markers.
func TestPendingSchema(t *testing.T) {
	good, e := encodePending(pendingRecord{"11111111-1111-1111-1111-111111111111", 100, WriterBudgetMS})
	if e != nil {
		t.Fatal(e)
	}
	_, e = decodePending(good)
	wantCode(t, e, "ok")
	bads := [][]byte{nil, []byte("{}\n"), append([]byte(" "), good...), good[:len(good)-1], append(append([]byte{}, good...), '\n'), bytes.Repeat([]byte{'x'}, MaxPending+1),
		bytes.Replace(good, []byte(`"budget_ms":1000`), []byte(`"budget_ms":999`), 1),
		bytes.Replace(good, []byte(`"started_ms":100`), []byte(`"started_ms":-1`), 1),
		bytes.Replace(good, []byte(`"started_ms":100`), []byte(`"started_ms":"100"`), 1),
		bytes.Replace(good, []byte(`"boot_id":"11111111-1111-1111-1111-111111111111"`), []byte(`"boot_id":"bad"`), 1),
		append(append([]byte{}, good[:len(good)-2]...), []byte(`,"extra":true}`+"\n")...),
		append(append([]byte{}, good[:len(good)-2]...), []byte(`,"budget_ms":1000}`+"\n")...),
	}
	for i, b := range bads {
		t.Run(fmt.Sprint(i), func(t *testing.T) { _, e := decodePending(b); wantCode(t, e, "journal_pending_malformed") })
	}
}

// TestReviewLateBrokenChain retains the reviewer's deeper witness: a valid third line passes and its broken predecessor refuses.
func TestReviewLateBrokenChain(t *testing.T) {
	_, e := Verify(bytes.NewReader(vector(t, "retiring")), genesis)
	wantCode(t, e, "ok")
	_, e = Verify(bytes.NewReader(vector(t, "late-broken-chain")), genesis)
	wantCode(t, e, "journal_chain")
}

// TestMaximumFenceDuration qualifies one exact-capacity normal append on this local filesystem; it is not a universal latency or power-loss proof.
func TestMaximumFenceDuration(t *testing.T) {
	if os.Getenv("GEN_JOURNAL_MEASURE") != "1" {
		t.Skip("explicit one-run maximum-size qualification only")
	}
	const stamp = "2026-10-01T00:00:00Z"
	record := func(seq, uid int64, state, prev string) []byte {
		b, e := Encode(Record{seq, prev, uid, fmt.Sprintf("%032x", seq), state, "operator-manual", stamp})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	// Distinct creating rows permit changing a few UID widths to fill the exact byte ceiling without padding or schema exceptions.
	n, total := int64(0), 0
	for {
		next := record(n+1, 30000+n, "creating", ZeroHash)
		tail := record(n+2, 30000+n, "active", ZeroHash)
		if total+len(next)+len(tail) > MaxFile {
			break
		}
		n++
		total += len(next)
	}
	last := record(n+1, 30000+n-1, "active", ZeroHash)
	gap := MaxFile - total - len(last)
	if gap < 0 || int64(gap) >= n-1 {
		t.Fatalf("cannot fill exact fixture: rows=%d gap=%d", n, gap)
	}
	data := make([]byte, 0, MaxFile)
	prev := ZeroHash
	for i := int64(1); i <= n; i++ {
		uid := 30000 + i - 1
		if i <= int64(gap) {
			uid = 100000 + i
		}
		b := record(i, uid, "creating", prev)
		data = append(data, b...)
		prev = Digest(b)
	}
	// Final active uses the last creating token, not its own sequence.
	final, e := Encode(Record{n + 1, prev, 30000 + n - 1, fmt.Sprintf("%032x", n), "active", "operator-manual", stamp})
	if e != nil {
		t.Fatal(e)
	}
	if len(data)+len(final) != MaxFile {
		t.Fatalf("fixture size %d", len(data)+len(final))
	}
	dir, p := fixture(t, data)
	tool := testTool(t, p)
	// Reuse the actual shell runbook; wrapper timestamps the marker's boot clock start and the successful finish before stdout.
	log := filepath.Join(p.anchor, "budget-clock")
	wrapper := filepath.Join(p.anchor, "measured-checker")
	script := fmt.Sprintf("#!/bin/sh\nset -eu\n'%s' \"$@\"\nif [ \"$1\" = intent ]; then cp '%s/writer.pending' '%s'; fi\n", tool, dir, log)
	if e = os.WriteFile(wrapper, []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	started := time.Now()
	out, e := runbook(t, wrapper, p, "append", dir, "0", ZeroHash, "1", "4294967294", fmt.Sprint(30000+n-1), fmt.Sprintf("%032x", n), "active", stamp)
	if e != nil {
		t.Fatalf("maximum-size append: %v %s", e, out)
	}
	elapsed := time.Since(started)
	b, e := os.ReadFile(log)
	if e != nil {
		t.Fatal(e)
	}
	m, e := decodePending(b)
	if e != nil {
		t.Fatal(e)
	}
	now, e := bootTimeMS()
	if e != nil {
		t.Fatal(e)
	}
	stored, e := os.ReadFile(filepath.Join(dir, "journal"))
	if e != nil {
		t.Fatal(e)
	}
	v, e := Verify(bytes.NewReader(stored), genesis)
	wantCode(t, e, "ok")
	if len(stored) != MaxFile || v.Tail.Seq != n+1 {
		t.Fatal("measurement was not at the exact file ceiling")
	}
	if _, e = os.Stat(filepath.Join(dir, "writer.pending")); !os.IsNotExist(e) {
		t.Fatal("successful measured writer retained marker")
	}
	t.Logf("exact final bytes=%d records=%d; complete runbook=%s; conservative marker-start through post-exit observation=%d ms; published normal fence budget=%d ms", len(stored), v.Tail.Seq, elapsed, now-m.StartedMS, WriterBudgetMS)
	if now-m.StartedMS >= WriterBudgetMS {
		t.Fatalf("qualification includes process exit overhead and exceeded budget: %d ms", now-m.StartedMS)
	}
}

// TestReconcileGuards preserves incident-path guard coverage: either failed verifier/clear helper stops the script without clearing the marker.
func TestReconcileGuards(t *testing.T) {
	for _, phase := range []string{"verify-locked", "clear-intent"} {
		t.Run(phase, func(t *testing.T) {
			dir, p := fixture(t, vector(t, "active"))
			real := testTool(t, p)
			if e := makeIntent(dir, p); e != nil {
				t.Fatal(e)
			}
			marker := filepath.Join(dir, "writer.pending")
			before, _ := os.ReadFile(marker)
			log := filepath.Join(p.anchor, "calls")
			wrapper := filepath.Join(p.anchor, "failing-checker")
			body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$1\" >> '%s'\nif [ \"$1\" = '%s' ]; then exit 23; fi\nexec '%s' \"$@\"\n", log, phase, real)
			if e := os.WriteFile(wrapper, []byte(body), 0755); e != nil {
				t.Fatal(e)
			}
			if out, e := runbook(t, wrapper, p, "reconcile", dir, "0", ZeroHash); e == nil {
				t.Fatalf("reconcile guard failed open: %s", out)
			}
			calls, _ := os.ReadFile(log)
			stages := strings.Fields(string(calls))
			after, e := os.ReadFile(marker)
			if e != nil || !bytes.Equal(before, after) || len(stages) == 0 || stages[len(stages)-1] != phase {
				t.Fatalf("continued or changed marker after guard: %s", calls)
			}
		})
	}
}
