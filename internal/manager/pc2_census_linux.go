//go:build linux

package manager

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
)

// Construction of the context/proof exists only in _test.go. The fixture
// transcript checks a concrete original reservation and independent commitment;
// it is deliberately not a production commit/custody API.
type censusContext struct {
	pc2, fence           *pc2store.ReadDirectory
	fenceID              pc2store.FileIdentity
	targets              []pc2store.HeadTarget
	native               map[string]*pc2store.ReadDirectory
	baseline             pc2store.SnapshotBaseline
	commit, commitDigest string
	probe                func(string)
}
type censusMarkerBinding struct {
	Marker  string `json:"marker_digest"`
	Attempt string `json:"attempt_digest"`
}
type censusFixtureCommit struct {
	Version         string               `json:"version"`
	Installation    string               `json:"installation_id"`
	Reservation     json.RawMessage      `json:"reservation"`
	Heads           []string             `json:"head_digests"`
	Index           pc2store.Head        `json:"index"`
	Funding         string               `json:"funding_digest"`
	Genesis         string               `json:"genesis"`
	Marker          *censusMarkerBinding `json:"marker_binding"`
	OriginalIntents []string             `json:"original_intents"`
	Origins         []string             `json:"hold_origins"`
	Effects         []State              `json:"effects_checkpoints"`
}
type censusRow struct {
	ID        string `json:"id"`
	Bytes     int64  `json:"bytes"`
	Integrity int64  `json:"integrity_bytes"`
}
type censusClass struct {
	Version string      `json:"version"`
	Owner   string      `json:"owner"`
	Kind    string      `json:"kind"`
	Objects []censusRow `json:"objects"`
}
type censusEvidence struct {
	Version      string                  `json:"version"`
	Installation string                  `json:"installation_id"`
	Commitment   string                  `json:"commitment"`
	Index        pc2store.Head           `json:"index"`
	Heads        []string                `json:"heads"`
	Native       []string                `json:"native_observations"`
	Held         int64                   `json:"held_bytes"`
	Envelope     int64                   `json:"envelope_bytes"`
	Prospective  []pc2store.CensusOutput `json:"prospective"`
	Verdict      SlotVerdict             `json:"slot_verdict"`
	Owner        string                  `json:"owner"`
}

func treeCensus(raw []byte) (map[string]any, error) {
	v, e := ccj.Parse(raw, ccj.RegistrationMalformed)
	if e != nil {
		return nil, e
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrCensusUnavailable
	}
	return m, nil
}
func digestCensus(raw []byte) string { return "sha256:" + digestBytes(raw) }
func boundCensus(n int64) bool       { return n >= 0 && n <= pc2state.AggregateBytes }

// reservationCensus checks the exact shared G4 representation and conservation;
// the independent fixture commit, not these counters, supplies fixture eligibility.
func reservationCensus(raw []byte) (string, int64, map[string]int64, error) {
	var q struct {
		Version string  `json:"version"`
		Base    *string `json:"base_root_digest"`
		Limit   int64   `json:"limit_bytes"`
		Groups  []struct {
			Owner     string `json:"owner"`
			Kind      string `json:"kind"`
			Inventory string `json:"inventory_digest"`
			Bytes     int64  `json:"materialized_bytes"`
			Integrity int64  `json:"integrity_bytes"`
			Reserved  int64  `json:"reserved_bytes"`
			Objects   int64  `json:"objects"`
		} `json:"groups"`
		Total int64 `json:"total_bytes"`
		Audit int64 `json:"audit_records_reserved"`
		Slots struct {
			Slots    int64 `json:"slots"`
			Attempt  int64 `json:"attempt_bytes"`
			Hold     int64 `json:"hold_bytes"`
			Guard    int64 `json:"guard_bytes"`
			Recovery int64 `json:"recovery_bytes"`
		} `json:"manager_slots"`
	}
	if len(raw) > 65536 || strict(raw, &q) != nil || q.Version != "keymaker-reservation/1" || q.Limit != pc2state.AggregateBytes || q.Audit != 8 || len(q.Groups) != 14 || q.Slots.Slots != 1 || q.Slots.Attempt != 4096 || q.Slots.Hold != 4096 || q.Slots.Guard != 65536 || q.Slots.Recovery != 65536 {
		return "", 0, nil, ErrCensusUnavailable
	}
	if q.Base != nil && !digestOKCensus(*q.Base) {
		return "", 0, nil, ErrCensusUnavailable
	}
	want := []string{"keymaker/artifacts", "keymaker/installed", "keymaker/migration_history", "keymaker/pending_proofs", "keymaker/policy_history", "keymaker/recovery", "keymaker/reservation_metadata", "keymaker/root_history", "keymaker/staging", "manager/attempts", "manager/holds", "manager/inventory", "manager/recovery", "manager/staging"}
	var total int64
	sources := map[string]int64{}
	for i, r := range q.Groups {
		if r.Owner+"/"+r.Kind != want[i] || !digestOKCensus(r.Inventory) || !boundCensus(r.Bytes) || !boundCensus(r.Integrity) || !boundCensus(r.Reserved) || !boundCensus(r.Objects) {
			return "", 0, nil, ErrCensusUnavailable
		}
		sources[r.Owner+"/"+r.Kind] = r.Reserved
		total += r.Bytes + r.Integrity + r.Reserved
		if total > pc2state.AggregateBytes {
			return "", 0, nil, ErrCensusUnavailable
		}
	}
	if total != q.Total {
		return "", 0, nil, ErrCensusUnavailable
	}
	return digestCensus(raw), total, sources, nil
}
func digestOKCensus(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && hashOK(s[7:])
}

func prepareManagerCensus(c *censusContext) (prepared *PreparedCensus, err error) {
	var envelope int64
	bad := func(e error) (*PreparedCensus, error) { return nil, &CensusRefusal{HeldEnvelope: envelope, Cause: e} }
	if c == nil || len(c.commit) > 65536 || digestCensus([]byte(c.commit)) != c.commitDigest {
		return bad(nil)
	}
	original := c
	local := *c
	local.targets = append([]pc2store.HeadTarget(nil), c.targets...)
	local.native = map[string]*pc2store.ReadDirectory{"native-effects": c.native["native-effects"], "native-generations": c.native["native-generations"]}
	c = &local
	var proof censusFixtureCommit
	if strict([]byte(c.commit), &proof) != nil || proof.Version != "pc2-census-fixture-commit/1" || !hex32Census(proof.Installation) || len(proof.Heads) != 5 || proof.OriginalIntents == nil || proof.Origins == nil || proof.Effects == nil || proof.Index != c.baseline.Head || proof.Funding != c.baseline.FundingDigest || proof.Genesis != c.baseline.Genesis {
		return bad(nil)
	}
	q, total, sources, e := reservationCensus(proof.Reservation)
	if e != nil {
		return bad(e)
	}
	c1, e := pc2store.CaptureHeads(c.fence, c.fenceID, c.targets)
	if e != nil {
		return bad(e)
	}
	for i, h := range c1 {
		if h.Digest != proof.Heads[i] {
			return bad(nil)
		}
	}
	if c.probe != nil {
		c.probe("captured")
	}
	snapshot, e := pc2store.ReadSnapshot(c.pc2, c.baseline)
	if e != nil {
		var debt *pc2store.SnapshotReadError
		if errors.As(e, &debt) {
			return nil, &CensusRefusal{ObservedBytes: debt.ObservedBytes, Cause: e}
		}
	}
	if e != nil || snapshot.Reservation() != q || snapshot.Envelope() > total {
		return bad(e)
	}
	envelope = snapshot.Envelope()
	for _, source := range snapshot.SourceReservations() {
		key := source.Owner + "/" + source.Kind
		sources[key] -= source.Bytes
		if sources[key] < 0 {
			return bad(nil)
		}
	}
	entries := snapshot.Entries()
	aliases := map[[2]uint64]bool{}
	ids := map[string]bool{}
	classes := [5]censusClass{}
	for i, k := range censusClasses {
		classes[i] = censusClass{string(pc2state.CapacityInventory), "manager", k, []censusRow{}}
	}
	add := func(id, class string, image pc2store.FileImage, integrity int64) error {
		key := [2]uint64{image.Identity.Device, image.Identity.Inode}
		if aliases[key] || ids[id] || image.Length() < 1 || !boundCensus(integrity) {
			return ErrCensusUnavailable
		}
		aliases[key] = true
		ids[id] = true
		for i, k := range censusClasses {
			if class == k {
				classes[i].Objects = append(classes[i].Objects, censusRow{id, image.Length(), integrity})
				return nil
			}
		}
		return ErrCensusUnavailable
	}
	for _, row := range entries {
		if e = add(row.ID, row.Class, row.Image, row.Integrity); e != nil {
			return bad(e)
		}
	}
	native := []nativeCensusImage{}
	held := snapshot.HeldBytes()
	for _, n := range snapshot.Native() {
		image, e := readCensusNative(c.native[n.Directory], n)
		if e != nil {
			return bad(e)
		}
		native = append(native, image)
		r, _ := pc2store.NativeRoleCatalog(n.Role)
		if e = add(n.StorageID, r.Class, image.image, n.Integrity); e != nil {
			return bad(e)
		}
		held -= n.Bytes + n.Integrity
	}
	if e = censusNativeClosure(c, native); e != nil {
		var debt *CensusRefusal
		if errors.As(e, &debt) {
			debt.HeldEnvelope = snapshot.Envelope()
			return nil, debt
		}
		return bad(e)
	}
	if e = censusNativeHistory(native, snapshot.History(), proof.Effects); e != nil {
		return bad(e)
	}
	if c.probe != nil {
		c.probe("native-read")
	}
	verdict, owner, e := censusSlot(c1, proof, entries, native, q)
	if e != nil {
		return bad(e)
	}
	out := &PreparedCensus{verdict: verdict, owner: owner}
	var materialized, objects, physical int64
	for i, cl := range classes {
		sort.Slice(cl.Objects, func(a, b int) bool { return cl.Objects[a].ID < cl.Objects[b].ID })
		raw, e := canonical(cl)
		if e != nil {
			return bad(e)
		}
		if _, e = pc2state.Decode(pc2state.CapacityInventory, raw); e != nil {
			return bad(e)
		}
		out.classes[i] = string(raw)
		for _, r := range cl.Objects {
			physical += r.Bytes + r.Integrity
			if i < 3 {
				materialized += r.Bytes
				objects++
			}
		}
	}
	if held < 0 || physical+held != snapshot.Envelope() {
		return bad(nil)
	}
	old, e := treeCensus(c1[2].Bytes())
	if e != nil {
		return bad(e)
	}
	if _, e = pc2state.Decode(pc2state.ManagerInventory, c1[2].Bytes()); e != nil {
		return bad(e)
	}
	if old["slot_reservation"] != q || old["materialized_bytes"] != materialized || old["objects"] != objects {
		return bad(nil)
	}
	for i, key := range []string{"attempts_digest", "holds_digest", "recovery_digest"} {
		if old[key] != digestCensus([]byte(out.classes[i])) {
			return bad(nil)
		}
	}
	revision := old["revision"].(int64)
	if revision == pc2state.SafeInteger {
		return bad(nil)
	}
	old["previous_digest"] = c1[2].Digest
	old["revision"] = revision + 1
	head, e := canonical(old)
	if e != nil {
		return bad(e)
	}
	if _, e = pc2state.Decode(pc2state.ManagerInventory, head); e != nil {
		return bad(e)
	}
	out.head = string(head)
	bounds := snapshot.OutputBounds()
	if len(bounds) != 6 {
		return bad(nil)
	}
	for _, b := range bounds {
		raw := out.ClassBytes(b.Kind)
		if b.Kind == "head" {
			raw = head
		}
		if len(raw) == 0 || int64(len(raw)) > b.MaxBytes {
			return bad(nil)
		}
	}
	if c.probe != nil {
		c.probe("validated")
	}
	// Repeated complete snapshots occur outside F; no Inspect/Head writer lock.
	second, e := pc2store.ReadSnapshot(c.pc2, c.baseline)
	if e != nil || !sameSnapshotCensus(snapshot, second) {
		return bad(e)
	}
	for _, n := range native {
		again, e := readCensusNative(c.native[n.observation.Directory], n.observation)
		if e != nil || again.image != n.image {
			return bad(errors.Join(errNativeCensus, e))
		}
	}
	c2, e := pc2store.CaptureHeads(c.fence, c.fenceID, c.targets)
	if e != nil {
		return bad(e)
	}
	for i := range c1 {
		if c1[i] != c2[i] {
			return bad(nil)
		}
	}
	third, e := pc2store.ReadSnapshot(c.pc2, c.baseline)
	if e != nil || !sameSnapshotCensus(snapshot, third) {
		return bad(e)
	}
	for _, n := range native {
		again, e := readCensusNative(c.native[n.observation.Directory], n.observation)
		if e != nil || again.image != n.image {
			return bad(errors.Join(errNativeCensus, e))
		}
	}
	if e = censusNativeClosure(c, native); e != nil {
		var debt *CensusRefusal
		if errors.As(e, &debt) {
			debt.HeldEnvelope = snapshot.Envelope()
			return nil, debt
		}
		return bad(e)
	}
	if digestCensus([]byte(c.commit)) != c.commitDigest || original.commitDigest != c.commitDigest || original.baseline != c.baseline {
		return bad(nil)
	}
	evidence := censusEvidence{"pc2-census-evidence/1", proof.Installation, c.commitDigest, c.baseline.Head, append([]string(nil), proof.Heads...), []string{}, held, snapshot.Envelope(), bounds, verdict, owner}
	for _, n := range snapshot.History() {
		b, _ := canonical(n)
		evidence.Native = append(evidence.Native, digestCensus(b))
	}
	eb, e := canonical(evidence)
	if e != nil {
		return bad(e)
	}
	out.evidence = string(eb)
	return out, nil
}
func hex32Census(s string) bool { return len(s) == 32 && hashOK(s+s) }
func sameSnapshotCensus(a, b pc2store.ReadSnapshotResult) bool {
	left, right := a.Entries(), b.Entries()
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	if len(left) != len(right) || a.Envelope() != b.Envelope() || a.HeldBytes() != b.HeldBytes() {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func censusNativeClosure(c *censusContext, images []nativeCensusImage) error {
	expected := map[string]bool{}
	roles := map[string]bool{}
	for _, n := range images {
		expected[n.observation.Directory+"/"+n.observation.Name] = true
		roles[n.observation.Role] = true
	}
	if !roles["generation-journal"] || !roles["effects-store"] {
		return ErrCensusUnavailable
	}
	for _, dir := range []string{"native-effects", "native-generations"} {
		d := c.native[dir]
		names, e := d.Names(258)
		if e != nil {
			return e
		}
		infrastructure := []string{"effects.lock"}
		mode := uint32(0600)
		if dir == "native-generations" {
			infrastructure = []string{"gate.lock", "data.lock"}
			mode = 0644
		}
		for _, name := range infrastructure {
			if _, e := d.Read(name, mode, 0); e != nil {
				return e
			}
		}
		for _, name := range names {
			if (dir == "native-effects" && name == "effects.lock") || (dir == "native-generations" && (name == "gate.lock" || name == "data.lock")) {
				mode := uint32(0600)
				if dir == "native-generations" {
					mode = 0644
				}
				im, e := d.Read(name, mode, 0)
				if e != nil || im.Length() != 0 {
					return ErrCensusUnavailable
				}
				continue
			}
			if !expected[dir+"/"+name] {
				mode := uint32(0600)
				if dir == "native-generations" {
					mode = 0644
				}
				image, e := d.Read(name, mode, 8388608)
				return &CensusRefusal{OrphanBytes: image.Length(), Cause: errors.Join(ErrCensusUnavailable, e)}
			}
		}
	}
	return nil
}

func censusSlot(heads []pc2store.FileImage, proof censusFixtureCommit, entries []pc2store.SnapshotEntry, native []nativeCensusImage, q string) (SlotVerdict, string, error) {
	unavailable := func() (SlotVerdict, string, error) { return SlotUnavailable, "", ErrCensusUnavailable }
	if _, e := pc2state.Decode(pc2state.RecoveryGuard, heads[1].Bytes()); e != nil {
		return unavailable()
	}
	guard, e := treeCensus(heads[1].Bytes())
	if e != nil {
		return unavailable()
	}
	ref := guard["inventory"].(map[string]any)
	if ref["digest"] != heads[2].Digest || ref["bytes"] != heads[2].Length() {
		return unavailable()
	}
	objects := map[string]pc2state.Object{}
	raws := map[string][]byte{}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Order < entries[j].Order })
	byEffect := map[string][]pc2state.AttemptLink{}
	latest := map[string]pc2state.Object{}
	for _, entry := range entries {
		raws[entry.Image.Digest] = entry.Image.Bytes()
		if entry.Codec != "" {
			o, e := pc2state.Decode(pc2state.Kind(entry.Codec), entry.Image.Bytes())
			if e != nil {
				return unavailable()
			}
			objects[entry.Image.Digest] = o
			if o.Kind() == pc2state.ActivationAttempt {
				m, _ := treeCensus(o.Bytes())
				effect := m["effect_digest"].(string)
				hist := byEffect[effect]
				prev := ""
				if len(hist) > 0 {
					prev, _ = pc2state.Digest(hist[len(hist)-1].Record)
				}
				byEffect[effect] = append(hist, pc2state.AttemptLink{Record: o, PreviousDigest: prev})
				latest[effect] = o
			}
		}
	}
	marker := ""
	for _, n := range native {
		raws[n.image.Digest] = n.image.Bytes()
		if n.observation.Encoding == "pending" {
			if marker != "" {
				return unavailable()
			}
			marker = n.image.Digest
		}
	}
	if retainedCensusLinks(objects, raws) != nil {
		return unavailable()
	}
	for effect, history := range byEffect {
		if pc2state.CheckAttemptHistory(history) != nil {
			return unavailable()
		}
		found := false
		for _, d := range proof.OriginalIntents {
			if d == effect && raws[d] != nil {
				found = true
			}
		}
		if !found {
			return unavailable()
		}
		for _, link := range history {
			attemptMap, _ := treeCensus(link.Record.Bytes())
			if censusAttemptJournal(attemptMap, native) != nil {
				return unavailable()
			}
			if pc2state.CheckEffectIntent(link.Record, raws[effect]) != nil {
				return unavailable()
			}
		}
	}
	for _, o := range objects {
		if o.Kind() == pc2state.Hold {
			found := false
			for _, d := range proof.Origins {
				if raw := raws[d]; raw != nil && pc2state.CheckHoldOrigin(o, raw) == nil {
					found = true
				}
			}
			if !found {
				return unavailable()
			}
		}
	}
	// All non-null guard/history references must resolve against this capture.
	for _, key := range []string{"attempt", "resolution", "release_prepared", "released"} {
		if guard[key] != nil {
			r := guard[key].(map[string]any)
			o, ok := objects[r["digest"].(string)]
			if !ok || string(o.Kind()) != r["codec"] || int64(len(o.Bytes())) != r["bytes"] {
				return unavailable()
			}
		}
	}
	for _, h := range guard["holds"].([]any) {
		m := h.(map[string]any)
		o, ok := objects[m["hold_id"].(string)]
		if !ok || o.Kind() != pc2state.Hold {
			return unavailable()
		}
		hm, _ := treeCensus(o.Bytes())
		if hm["kind"] != m["kind"] || hm["origin_id"] != m["origin_id"] {
			return unavailable()
		}
		if m["kind"] == "authority" {
			return unavailable()
		}
	}
	if guard["phase"] == "clear" {
		if len(byEffect) != 0 || marker != "" {
			return unavailable()
		}
		for _, o := range objects {
			if o.Kind() == pc2state.Hold || o.Kind() == pc2state.RecoveryRecord {
				return unavailable()
			}
		}
		return SlotUnspent, "", nil
	}
	if guard["phase"] != "open" || guard["attempt"] == nil || len(byEffect) != 1 {
		return unavailable()
	}
	attemptRef := guard["attempt"].(map[string]any)
	o := objects[attemptRef["digest"].(string)]
	m, _ := treeCensus(o.Bytes())
	if m["disposition"] != "pending" {
		return unavailable()
	}
	if m["manager_id"] != proof.Installation || guard["source_root_digest"] != heads[0].Digest || m["source"].(map[string]any)["root_digest"] != heads[0].Digest {
		return unavailable()
	}
	for _, h := range guard["holds"].([]any) {
		if h.(map[string]any)["origin_id"] != m["attempt_id"] {
			return unavailable()
		}
	}
	if latest[m["effect_digest"].(string)] != o {
		return unavailable()
	}
	if marker != "" {
		if proof.Marker == nil || proof.Marker.Marker != marker || proof.Marker.Attempt != attemptRef["digest"] {
			return unavailable()
		}
	} else if proof.Marker != nil {
		return unavailable()
	}
	if q == "" {
		return unavailable()
	}
	return SlotOccupied, m["attempt_id"].(string), nil
}
