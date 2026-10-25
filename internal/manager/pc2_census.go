package manager

import "errors"

var ErrCensusUnavailable = errors.New("manager census unavailable")

// CensusRefusal preserves measured retained debt as diagnostics. Unknown
// provenance/overhead still forbids an accepting census; these are not free bytes.
type CensusRefusal struct {
	ObservedBytes, OrphanBytes, HeldEnvelope int64
	Cause                                    error
}

func (e *CensusRefusal) Error() string   { return "manager census unavailable; retained debt" }
func (e *CensusRefusal) Unwrap() []error { return []error{ErrCensusUnavailable, e.Cause} }

type SlotVerdict string

const (
	SlotUnavailable SlotVerdict = "unavailable"
	SlotUnspent     SlotVerdict = "unspent-committed-credit"
	SlotOccupied    SlotVerdict = "exact-occupied-owner"
)

// PreparedCensus is immutable snapshot evidence, never an admission grant,
// one-use credit capability, currentness provider or descriptor lease.
type PreparedCensus struct {
	classes        [5]string
	head, evidence string
	verdict        SlotVerdict
	owner          string
}

func (p *PreparedCensus) ClassBytes(kind string) []byte {
	if p == nil {
		return nil
	}
	for i, k := range censusClasses {
		if kind == k {
			return []byte(p.classes[i])
		}
	}
	return nil
}
func (p *PreparedCensus) HeadBytes() []byte {
	if p == nil {
		return nil
	}
	return []byte(p.head)
}
func (p *PreparedCensus) EvidenceBytes() []byte {
	if p == nil {
		return nil
	}
	return []byte(p.evidence)
}
func (p *PreparedCensus) Slot() (SlotVerdict, string) {
	if p == nil || p.evidence == "" {
		return SlotUnavailable, ""
	}
	return p.verdict, p.owner
}

var censusClasses = [...]string{"attempts", "holds", "recovery", "inventory", "staging"}

// PrepareManagerCensus has no installed authority producer. In particular no
// caller flags, paths, maps, root privilege or fixture selector can enable it.
func PrepareManagerCensus() (*PreparedCensus, error) { return nil, ErrCensusUnavailable }
