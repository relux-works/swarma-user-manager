package qualmaint

import (
	"bufio"
	"bytes"
	"io"
	"reflect"
)

type Checkpoint struct {
	Seq    uint64
	SHA256 string
}

func (c Checkpoint) valid() bool {
	return c.Seq == 0 && c.SHA256 == Zero || c.Seq > 0 && c.Seq <= JournalEntries && digestOK(c.SHA256)
}

// History reports structural integrity and historical phases, never admission.
// An open attempt is retained, not silently closed or promoted by replay.
type History struct {
	Checkpoint   Checkpoint
	Entries      []Entry
	Open         *Entry
	LastAccepted *Entry
	Advances     uint64
}

func same(a, b any) bool { return reflect.DeepEqual(a, b) }
func binding(e Entry) Entry {
	e.Seq = 0
	e.Prev = ""
	e.Phase = ""
	e.Reason = ""
	e.Step = 0
	e.InitialQ = nil
	e.Unit = nil
	e.Notification = Notification{}
	e.BootID = ""
	return e
}
func exactAcceptedSet(a, b Entry) bool {
	return a.OldInputs == b.OldInputs && a.CandidateInputs == b.CandidateInputs && a.OldState == b.OldState && a.CandidateState == b.CandidateState && a.TransactionManifest == b.TransactionManifest && same(a.Transactions, b.Transactions)
}
func receiptAdvance(old, next Recipient) (bool, bool) {
	if same(old, next) {
		return false, true
	}
	if old.State == "pending" && next.State == "delivered" && next.Receipt != nil {
		return true, true
	}
	return false, false
}
func notificationUpdate(old, next Entry) bool {
	if old.Phase != "refused" && old.Phase != "interrupted" {
		return false
	}
	a, b := old, next
	a.Seq = 0
	b.Seq = 0
	a.Prev = ""
	b.Prev = ""
	a.Notification = Notification{}
	b.Notification = Notification{}
	if !same(a, b) || !same(old.Notification.Incident, next.Notification.Incident) {
		return false
	}
	owner, ok1 := receiptAdvance(old.Notification.Owner, next.Notification.Owner)
	curator, ok2 := receiptAdvance(old.Notification.Curator, next.Notification.Curator)
	return ok1 && ok2 && (owner || curator)
}
func invocations(groups []Transaction) map[ID]*ID {
	out := map[ID]*ID{}
	for _, g := range groups {
		for _, id := range g.Invocations {
			out[id] = g.Aggregate
		}
	}
	return out
}
func covers(next, old []Transaction) bool {
	a, b := invocations(next), invocations(old)
	for id, parent := range b {
		p, ok := a[id]
		if !ok || !same(p, parent) {
			return false
		}
	}
	return true
}

// Replay verifies every line, the retained checkpoint, local set associations,
// immutable transitions and exact accepted retries. It does not resolve external
// evidence or prove recorder chronology; those obligations belong to integration.
func Replay(r io.Reader, retained Checkpoint) (History, error) {
	h := History{Checkpoint: Checkpoint{0, Zero}}
	fail := func(err error) (History, error) { return History{}, err }
	if !retained.valid() {
		return fail(ErrChain)
	}
	reader := bufio.NewReaderSize(io.LimitReader(r, JournalBytes+1), EntryBytes+1)
	var total int64
	intents := map[uint64]Entry{}
	terminal := map[uint64]Entry{}
	acceptedIDs := map[ID]bool{}
	acceptedAggregates := map[ID]bool{}
	matched := retained.Seq == 0
	var initial *Entry
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) == 0 && err == io.EOF {
			break
		}
		total += int64(len(line))
		if total > JournalBytes || len(line) > EntryBytes || len(h.Entries) >= JournalEntries {
			return fail(ErrSaturated)
		}
		if err != nil {
			return fail(ErrRecord)
		}
		e, err := Decode(line)
		if err != nil {
			return fail(err)
		}
		if e.Seq != h.Checkpoint.Seq+1 || e.Prev != h.Checkpoint.SHA256 {
			return fail(ErrChain)
		}
		if e.Phase == "intent" {
			if h.Open != nil {
				return fail(ErrID)
			}
			retry, found := terminal[e.RetryOf]
			acceptedRetry := e.RetryOf != 0 && found && retry.Phase == "accepted"
			if e.RetryOf != 0 && (!found || !covers(e.Transactions, retry.Transactions)) {
				return fail(ErrCoverage)
			}
			if acceptedRetry {
				if h.LastAccepted == nil || retry.Attempt != h.LastAccepted.Attempt || !exactAcceptedSet(e, retry) {
					return fail(ErrCoverage)
				}
			} else {
				if h.LastAccepted != nil {
					if e.OldState != h.LastAccepted.CandidateState || e.OldInputs != h.LastAccepted.CandidateInputs {
						return fail(ErrCoverage)
					}
				} else if initial != nil && (e.OldState != initial.OldState || e.OldInputs != initial.OldInputs) {
					return fail(ErrCoverage)
				}
				for _, g := range e.Transactions {
					if g.Aggregate != nil && acceptedAggregates[*g.Aggregate] {
						return fail(ErrID)
					}
					for _, id := range g.Invocations {
						if acceptedIDs[id] {
							return fail(ErrID)
						}
					}
				}
				// A new endpoint must retain every unresolved failed transaction, even
				// when no retry_of shorthand is supplied. It cannot silently discard work.
				for id, t := range terminal {
					if t.Phase == "accepted" {
						continue
					}
					unresolved := false
					for inv := range invocations(t.Transactions) {
						if !acceptedIDs[inv] {
							unresolved = true
						}
					}
					if unresolved && !covers(e.Transactions, intents[id].Transactions) {
						return fail(ErrCoverage)
					}
				}
			}
			if initial == nil {
				x := e
				initial = &x
			}
			intents[e.Attempt] = e
			x := e
			h.Open = &x
		} else if old, exists := terminal[e.Attempt]; exists {
			if !notificationUpdate(old, e) {
				return fail(ErrID)
			}
			terminal[e.Attempt] = e
		} else {
			intent, exists := intents[e.Attempt]
			if !exists || h.Open == nil || h.Open.Attempt != e.Attempt || !same(binding(e), binding(intent)) {
				return fail(ErrID)
			}
			if e.BootID != intent.BootID {
				if e.Phase != "interrupted" || e.Reason != "crash_recovery" || e.InitialQ != nil || e.Unit != nil {
					return fail(ErrRecord)
				}
			}
			terminal[e.Attempt] = e
			h.Open = nil
			if e.Phase == "accepted" {
				prior, isRetry := terminal[e.RetryOf]
				if !isRetry || prior.Phase != "accepted" {
					h.Advances++
				}
				for _, g := range e.Transactions {
					if g.Aggregate != nil {
						acceptedAggregates[*g.Aggregate] = true
					}
					for _, id := range g.Invocations {
						acceptedIDs[id] = true
					}
				}
				x := e
				h.LastAccepted = &x
			}
		}
		h.Entries = append(h.Entries, e)
		h.Checkpoint = Checkpoint{e.Seq, Digest(line)}
		if retained.Seq == e.Seq {
			if retained.SHA256 != h.Checkpoint.SHA256 {
				return fail(ErrChain)
			}
			matched = true
		}
	}
	if !matched {
		return fail(ErrChain)
	}
	return h, nil
}

// VerifyReferences resolves every direct journal reference by exact bytes and
// size. This is an integrity check, not the owning evidence codec's semantic or
// authority validator. Missing authentic objects in the published vectors fail.
func VerifyReferences(h History, read func(Ref) ([]byte, error)) error {
	if read == nil {
		return ErrMissing
	}
	for _, e := range h.Entries {
		for _, r := range references(e) {
			b, err := read(r)
			if err != nil {
				return err
			}
			if int64(len(b)) != r.Size || Digest(b) != r.SHA256 {
				return ErrEvidence
			}
		}
	}
	return nil
}
func references(e Entry) []Ref {
	out := []Ref{e.CandidateState, e.EvidenceManifest, e.Interlock, e.OldState, e.Plan, e.TransactionManifest}
	if e.InitialQ != nil {
		out = append(out, *e.InitialQ)
	}
	if e.Unit != nil {
		out = append(out, e.Unit.Q)
	}
	for _, l := range e.Links {
		out = append(out, l.Object)
	}
	n := e.Notification
	if n.Incident != nil {
		out = append(out, *n.Incident)
	}
	if n.Owner.Receipt != nil {
		out = append(out, *n.Owner.Receipt)
	}
	if n.Curator.Receipt != nil {
		out = append(out, *n.Curator.Receipt)
	}
	return out
}

// Verify combines bounded whole-chain replay with direct-object integrity.
// It deliberately exposes no readiness or accepted-frontier mutation API.
func Verify(raw []byte, retained Checkpoint, read func(Ref) ([]byte, error)) (History, error) {
	h, err := Replay(bytes.NewReader(raw), retained)
	if err != nil {
		return History{}, err
	}
	if err = VerifyReferences(h, read); err != nil {
		return History{}, err
	}
	return h, nil
}
