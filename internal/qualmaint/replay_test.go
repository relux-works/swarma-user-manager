package qualmaint

import (
	"bytes"
	"context"
	"testing"
)

var empty = Checkpoint{0, Zero}

func replay(t *testing.T, b []byte) History {
	t.Helper()
	h, e := Replay(bytes.NewReader(b), empty)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func interrupted(t *testing.T, intent Entry) Entry {
	t.Helper()
	e := sample(t, "interrupted")
	e.Attempt = intent.Attempt
	e.RetryOf = intent.RetryOf
	e.Transactions = intent.Transactions
	e.TransactionManifest = intent.TransactionManifest
	e.OldInputs = intent.OldInputs
	e.CandidateInputs = intent.CandidateInputs
	e.OldState = intent.OldState
	e.CandidateState = intent.CandidateState
	e.EvidenceManifest = intent.EvidenceManifest
	e.Plan = intent.Plan
	e.Interlock = intent.Interlock
	e.Links = intent.Links
	return e
}

// All predecessor/sequence/checkpoint/tail violations refuse the whole result;
// no earlier successful prefix leaks out as a passing replay.
func TestQualMaintChain(t *testing.T) {
	i, a := sample(t, "intent"), sample(t, "accepted")
	valid := chain(t, i, a)
	good := replay(t, valid)
	cases := map[string][]byte{
		"tamper":            bytes.Replace(valid, []byte(`"candidate_inputs":"2`), []byte(`"candidate_inputs":"3`), 1),
		"wrong-predecessor": append(mustLine(t, i), wire(t, vector(t, "accepted"), func(m map[string]any) { m["prev"] = Digest([]byte("another predecessor")) })...),
		"sequence-reuse":    append(mustLine(t, i), mustLine(t, i)...),
		"sequence-gap":      append(mustLine(t, i), wire(t, vector(t, "accepted"), func(m map[string]any) { m["seq"] = 3 })...),
		"truncated-tail":    valid[:len(valid)-1], "corrupt-tail": append(append([]byte{}, valid...), []byte("garbage\n")...),
	}
	for n, b := range cases {
		t.Run(n, func(t *testing.T) {
			h, err := Replay(bytes.NewReader(b), empty)
			want := error(ErrChain)
			if n == "truncated-tail" || n == "corrupt-tail" {
				want = ErrRecord
			}
			wantError(t, err, want)
			if len(h.Entries) != 0 || h.LastAccepted != nil {
				t.Fatalf("partial authority escaped: %v", err)
			}
		})
	}
	for _, floor := range []Checkpoint{{3, good.Checkpoint.SHA256}, {2, Digest([]byte("wrong checkpoint"))}} {
		_, err := Replay(bytes.NewReader(valid), floor)
		wantError(t, err, ErrChain)
	}
	if h, err := Replay(bytes.NewReader(valid), good.Checkpoint); err != nil || h.Advances != 1 || h.Open != nil {
		t.Fatal(h, err)
	}
}

// Only intent-to-terminal transitions are legal; accepted shape is not allowed
// to bypass an open attempt, frozen identities or both qualification refs.
func TestQualMaintPhases(t *testing.T) {
	i, a := sample(t, "intent"), sample(t, "accepted")
	cases := map[string][]Entry{"orphan": {a}, "second-terminal": {i, a, a}}
	second := i
	second.Attempt = 2
	second.Seq = 2
	cases["second-open"] = []Entry{i, second}
	changed := a
	changed.CandidateInputs = changed.OldInputs
	cases["changed-input"] = []Entry{i, changed}
	for n, es := range cases {
		t.Run(n, func(t *testing.T) {
			_, err := Replay(bytes.NewReader(chain(t, es...)), empty)
			wantError(t, err, ErrID)
		})
	}
	a.InitialQ = nil
	if _, err := Encode(a); err != ErrRecord {
		t.Fatal(err)
	}
	if h := replay(t, chain(t, i)); h.Open == nil || h.LastAccepted != nil {
		t.Fatal("intent promoted")
	}
	f := interrupted(t, i)
	f.BootID = "22222222-2222-2222-2222-222222222222"
	f.Reason = "crash_recovery"
	if h := replay(t, chain(t, i, f)); h.LastAccepted != nil || h.Open != nil {
		t.Fatal("recovery acceptance")
	}
	f.Phase = "refused"
	if _, err := Replay(bytes.NewReader(chain(t, i, f)), empty); err != ErrRecord {
		t.Fatal(err)
	}
}

// Exact accepted retry refreshes historical proof but advances the frontier once;
// different set/baseline or reuse without retry_of is rejected.
func TestQualMaintExactRetry(t *testing.T) {
	i, a := sample(t, "intent"), sample(t, "accepted")
	retry := i
	retry.Attempt = 3
	retry.Seq = 3
	retry.RetryOf = 1
	result := a
	result.Attempt = 3
	result.RetryOf = 1
	h := replay(t, chain(t, i, a, retry, result))
	if h.Advances != 1 || h.LastAccepted.Attempt != 3 {
		t.Fatal(h)
	}
	for _, change := range []func(*Entry){func(e *Entry) { e.TransactionManifest = e.OldState }, func(e *Entry) { e.RetryOf = 0 }, func(e *Entry) { e.CandidateState = e.OldState }, func(e *Entry) { e.Transactions = []Transaction{{Invocations: []ID{{"new", "invocation", 3}}}} }} {
		r := retry
		change(&r)
		if _, err := Replay(bytes.NewReader(chain(t, i, a, r)), empty); err != ErrCoverage {
			t.Fatal("inexact accepted retry", err)
		}
	}
	next := i
	next.Attempt = 3
	next.Seq = 3
	next.OldState = a.CandidateState
	next.OldInputs = a.CandidateInputs
	next.Transactions = []Transaction{{Invocations: []ID{{"new", "invocation", 3}}}}
	if h := replay(t, chain(t, i, a, next)); h.Open == nil {
		t.Fatal("valid successor")
	}
}

// Failed-set retries retain every invocation/parent, including when retry_of
// is omitted. Replaying endpoint hashes alone cannot discard unresolved work.
func TestQualMaintFailedSetCoverage(t *testing.T) {
	i := sample(t, "intent")
	f := interrupted(t, i)
	r := i
	r.Attempt = 3
	r.Seq = 3
	r.RetryOf = 1
	if h := replay(t, chain(t, i, f, r)); h.Open == nil {
		t.Fatal("retry")
	}
	r.Transactions = []Transaction{{Invocations: []ID{{"new", "invocation", 2}}}}
	for _, retryOf := range []uint64{0, 1} {
		r.RetryOf = retryOf
		if _, err := Replay(bytes.NewReader(chain(t, i, f, r)), empty); err != ErrCoverage {
			t.Fatal(err)
		}
	}
}

// A later writer boot changes only delivery snapshots and seq/prev. Terminal
// boot, incident, existing receipts and qualification fields cannot be rewritten.
func TestQualMaintNotificationLaterBoot(t *testing.T) {
	i := sample(t, "intent")
	f := interrupted(t, i)
	update := f
	r := f.OldState
	update.Notification.Owner = Recipient{&r, "delivered"}
	// No current-writer boot is supplied to replay: history deliberately preserves
	// f.BootID. Clock/transport authentication remains a later integration test.
	h := replay(t, chain(t, i, f, update))
	if h.Advances != 0 || h.Entries[2].BootID != f.BootID {
		t.Fatal(h)
	}
	for n, change := range map[string]func(*Entry){
		"boot-rewrite":     func(e *Entry) { e.BootID = "22222222-2222-2222-2222-222222222222" },
		"incident-rewrite": func(e *Entry) { r := e.CandidateState; e.Notification.Incident = &r },
		"no-advance":       func(e *Entry) { e.Notification = f.Notification },
		"reason-rewrite":   func(e *Entry) { e.Reason = "io_unknown" },
	} {
		t.Run(n, func(t *testing.T) {
			e := update
			change(&e)
			_, err := Replay(bytes.NewReader(chain(t, i, f, e)), empty)
			wantError(t, err, ErrID)
		})
	}
	// Updates to older terminal attempts remain valid after a new open attempt.
	next := i
	next.Seq = 3
	next.Attempt = 3
	replay(t, chain(t, i, f, next, update))
	delivered := update
	downgrade := f
	_, err := Replay(bytes.NewReader(chain(t, i, f, delivered, downgrade)), empty)
	wantError(t, err, ErrID)
}

// A reference hash is an integrity assertion only; absent or mismatched objects
// refuse even when the chain has an accepted record with the published shape.
func TestQualMaintObjectMismatch(t *testing.T) {
	b := chain(t, sample(t, "intent"), sample(t, "accepted"))
	h := replay(t, b)
	if err := VerifyReferences(h, nil); err != ErrMissing {
		t.Fatal(err)
	}
	_, err := Verify(b, empty, func(Ref) ([]byte, error) { return []byte("wrong"), nil })
	wantError(t, err, ErrEvidence)
	_, err = Verify(b, empty, func(Ref) ([]byte, error) { return nil, ErrMissing })
	wantError(t, err, ErrMissing)
	// Independent valid content-integrity control (not an authority validator).
	payload := []byte("bounded retained object")
	r := Ref{Digest(payload), int64(len(payload))}
	e := sample(t, "intent")
	e.CandidateState = r
	e.EvidenceManifest = r
	e.Interlock = r
	e.OldState = r
	e.Plan = r
	e.TransactionManifest = r
	_, err = Verify(chain(t, e), empty, func(Ref) ([]byte, error) { return payload, nil })
	if err != nil {
		t.Fatal(err)
	}
}

// Deadline expiry rejects the whole replay instead of returning an earlier
// prefix. The same bounded chain with a live context is the valid control.
func TestQualMaintReplayDeadline(t *testing.T) {
	b := chain(t, sample(t, "intent"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h, err := ReplayContext(ctx, bytes.NewReader(b), empty)
	wantError(t, err, ErrLease)
	if len(h.Entries) != 0 {
		t.Fatal("partial replay")
	}
	if _, err = ReplayContext(context.Background(), bytes.NewReader(b), empty); err != nil {
		t.Fatal(err)
	}
}

// Published predecessor/checkpoint constants are independent of this package's
// chain-building helper: hashing without LF cannot make both sides agree.
func TestQualMaintPublishedChain(t *testing.T) {
	raw := append(append([]byte{}, vector(t, "intent")...), vector(t, "accepted")...)
	floor := Checkpoint{2, "551046db704954fdeff00a3deb8b47bbc32a0b6b484ed23b8de10a7a0003019f"}
	h, err := Replay(bytes.NewReader(raw), floor)
	if err != nil || h.Checkpoint != floor || h.Entries[1].Prev != "d3480ee51fe047ec1d68696878a00d6340500e3a98ec2712dbb175b6b85997a4" {
		t.Fatal("published line identity", err)
	}
}
