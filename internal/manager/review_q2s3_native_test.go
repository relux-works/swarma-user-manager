//go:build linux

package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Fixture constructor copied from exact candidate and limited to a complete
// effects-store temporary instead of evidence, with independent next-state proof.
func reviewNativeStageFixture(t *testing.T, opt censusOptions, advanced bool, extraRole string, headBound int64) *censusFixture {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	for name, mode := range map[string]os.FileMode{"pc2": 0750, "effects": 0700, "generations": 0755, "auth": 0750, "fence": 0750} {
		censusDir(t, filepath.Join(root, name), mode)
	}
	for _, rel := range []string{"attempts", "holds", "recovery", "inventory", "capacity", "staging", "inventory/owner-index", "inventory/owner-index/records", "inventory/owner-index/heads", "inventory/owner-index/pending"} {
		censusDir(t, filepath.Join(root, "pc2", rel), 0750)
	}
	p, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	})
	c := &censusContext{pc2: censusPin(t, p, "pc2", 0750), fence: censusPin(t, p, "fence", 0750), native: map[string]*pc2store.ReadDirectory{}}
	c.native["native-effects"] = censusPin(t, p, "effects", 0700)
	c.native["native-generations"] = censusPin(t, p, "generations", 0755)
	auth := censusPin(t, p, "auth", 0750)
	f := &censusFixture{c: c, root: root}
	censusWrite(t, filepath.Join(root, "fence/authority.lock"), nil, 0640)
	lock, e := c.fence.Read("authority.lock", 0640, 0)
	if e != nil {
		t.Fatal(e)
	}
	c.fenceID = lock.Identity
	for _, name := range []string{"effects/effects.lock", "generations/gate.lock", "generations/data.lock"} {
		mode := os.FileMode(0600)
		if strings.HasPrefix(name, "generations/") {
			mode = 0644
		}
		censusWrite(t, filepath.Join(root, name), nil, mode)
	}
	// A canonical complete fourteen-row reservation with explicit original
	// metadata/native reservations, not a caller slot count or sizing boolean.
	groups := []map[string]any{}
	kinds := []string{"keymaker/artifacts", "keymaker/installed", "keymaker/migration_history", "keymaker/pending_proofs", "keymaker/policy_history", "keymaker/recovery", "keymaker/reservation_metadata", "keymaker/root_history", "keymaker/staging", "manager/attempts", "manager/holds", "manager/inventory", "manager/recovery", "manager/staging"}
	for _, key := range kinds {
		parts := strings.Split(key, "/")
		reserved := int64(0)
		if key == "keymaker/reservation_metadata" || key == "manager/recovery" {
			reserved = 32 * 1024 * 1024
		}
		if key == "manager/attempts" || key == "manager/holds" {
			reserved = 4 * 1024 * 1024
		}
		if opt.underfunded && key == "keymaker/reservation_metadata" {
			reserved = 0
		}
		if opt.underfunded && key == "manager/recovery" {
			reserved += 32 * 1024 * 1024
		}
		groups = append(groups, map[string]any{"owner": parts[0], "kind": parts[1], "inventory_digest": "sha256:" + strings.Repeat("a", 64), "materialized_bytes": int64(0), "integrity_bytes": int64(0), "reserved_bytes": reserved, "objects": int64(0)})
	}
	qRaw := censusWire(t, map[string]any{"version": "keymaker-reservation/1", "base_root_digest": nil, "limit_bytes": pc2state.AggregateBytes, "groups": groups, "total_bytes": int64(72 * 1024 * 1024), "audit_records_reserved": int64(8), "manager_slots": map[string]any{"slots": int64(1), "attempt_bytes": int64(4096), "hold_bytes": int64(4096), "guard_bytes": int64(65536), "recovery_bytes": int64(65536)}})
	q := digestCensus(qRaw)
	rootRaw := censusWire(t, map[string]any{"fixture": "independent-root-binding", "reservation": q})
	for name, raw := range map[string][]byte{"root.json": rootRaw, "floor.json": censusWire(t, map[string]any{"floor": int64(3), "root": digestCensus(rootRaw)}), "intent.json": censusWire(t, map[string]any{"fixture": "explicit-clear-intent"})} {
		censusWrite(t, filepath.Join(root, "auth", name), raw, 0640)
	}
	first, e := genjournal.Encode(genjournal.Record{Seq: 1, Prev: genjournal.ZeroHash, UID: 10, Generation: strings.Repeat("1", 32), State: "creating", Writer: "user-manager", Time: "2026-10-25T00:00:00Z"})
	if e != nil {
		t.Fatal(e)
	}
	second, e := genjournal.Encode(genjournal.Record{Seq: 2, Prev: genjournal.Digest(first), UID: 10, Generation: strings.Repeat("1", 32), State: "active", Writer: "user-manager", Time: "2026-10-25T00:00:01Z"})
	if e != nil {
		t.Fatal(e)
	}
	f.journal = append(append([]byte{}, first...), second...)
	view, e := genjournal.Verify(bytes.NewReader(f.journal), genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	state := State{Format: stateFormat, Floor: view.Tail, Cursor: 1, Revision: 1, Effects: []Effect{}, OSRecords: []OSRecord{}}
	var nativeEvidence map[string]json.RawMessage
	if opt.history {
		h := setup(t)
		h.created(t)
		state = clone(h.s.state)
		state.Floor, state.Revision = view.Tail, 1
		nativeEvidence = h.s.evidence
	}
	priorState := clone(state)
	if opt.nativeReplace {
		state.Revision++
	}
	effects, e := effectBytes(state)
	if e != nil {
		t.Fatal(e)
	}
	type nativeSeed struct {
		role, name string
		raw        []byte
	}
	seeds := []nativeSeed{{"generation-journal", "journal", f.journal}, {"effects-store", "effects.json", effects}, {"effects-ledger", "ledger.json", censusWire(t, view)}}
	if extraRole != "" && extraRole != "unlisted-authority-hold" {
		raw := censusWire(t, map[string]any{"fixture": "independently-funded-retained-evidence"})
		seeds = append(seeds, nativeSeed{extraRole, "evidence-" + digestBytes(raw) + ".json", raw})
	}

	f.proof = censusFixtureCommit{Version: "pc2-census-fixture-commit/1", Installation: strings.Repeat("1", 32), Reservation: qRaw, OriginalIntents: []string{}, Origins: []string{}, Heads: []string{}, Effects: []State{clone(state)}}
	if opt.nativeReplace {
		f.proof.Effects = []State{priorState, clone(state)}
	}
	if opt.nativeStage || opt.nativeRename {
		staged := clone(state)
		if advanced {
			staged.Revision++
		}
		stageBytes, err := effectBytes(staged)
		if err != nil {
			t.Fatal(err)
		}
		if advanced {
			f.proof.Effects = append(f.proof.Effects, staged)
		}
		seeds = append(seeds, nativeSeed{"effects-temporary", ".write-" + strings.Repeat("e", 32), stageBytes})
	}
	keys := make([]string, 0, len(nativeEvidence))
	for key := range nativeEvidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		seeds = append(seeds, nativeSeed{"recovery-evidence", "evidence-" + key + ".json", nativeEvidence[key]})
	}
	var attempt, hold pc2state.Object
	if opt.occupied {
		original := censusWire(t, map[string]any{"operation": "fixture-original-intent", "effect": "one"})
		f.proof.OriginalIntents = append(f.proof.OriginalIntents, digestCensus(original))
		seeds = append(seeds, nativeSeed{"recovery-evidence", "evidence-" + digestBytes(original) + ".json", original})
		pre, e := os.ReadFile("../pc2state/testdata/attempt-preimage.json")
		if e != nil {
			t.Fatal(e)
		}
		m, e := treeCensus(pre)
		if e != nil {
			t.Fatal(e)
		}
		m["effect_digest"] = digestCensus(original)
		m["prepared_tail"] = map[string]any{"seq": view.Tail.Seq, "hash": view.Tail.Hash}
		m["active_record_hash"] = genjournal.Digest(second)
		m["source"].(map[string]any)["authority_incarnation"] = strings.Repeat("2", 32)
		m["manager_id"] = f.proof.Installation
		m["source"].(map[string]any)["root_digest"] = digestCensus(rootRaw)
		attempt, e = pc2state.NewPendingAttempt(censusWire(t, m))
		if e != nil {
			t.Fatal(e)
		}
		pre, e = pc2state.AttemptPreimage(attempt)
		if e != nil {
			t.Fatal(e)
		}
		hold, e = pc2state.NewHold("activation", pre)
		if e != nil {
			t.Fatal(e)
		}
		f.proof.Origins = append(f.proof.Origins, digestCensus(pre))
		seeds = append(seeds, nativeSeed{"attempt-evidence", "evidence-" + digestBytes(pre) + ".json", pre})
		f.payloads = append(f.payloads, censusPayload{role: "attempts", codec: string(pc2state.ActivationAttempt), raw: attempt.Bytes()})
	}
	if opt.authority {
		origin, e := os.ReadFile("../pc2state/testdata/transaction.json")
		if e != nil {
			t.Fatal(e)
		}
		hold, e = pc2state.NewHold("authority", origin)
		if e != nil {
			t.Fatal(e)
		}
		f.proof.Origins = append(f.proof.Origins, digestCensus(origin))
		seeds = append(seeds, nativeSeed{"hold-evidence", "evidence-" + digestBytes(origin) + ".json", origin})
	}
	if len(hold.Bytes()) > 0 {
		f.payloads = append(f.payloads, censusPayload{role: "holds", codec: string(pc2state.Hold), raw: hold.Bytes()})
	}
	if opt.marker {
		marker := append(censusWire(t, map[string]any{"format": "gen-journal-pending/1", "boot_id": "00000000-0000-4000-8000-000000000001", "started_ms": int64(1), "budget_ms": int64(1000)}), '\n')
		seeds = append(seeds, nativeSeed{"generation-pending", "writer.pending", marker})
		if opt.occupied {
			f.proof.Marker = &censusMarkerBinding{digestCensus(marker), digestCensus(attempt.Bytes())}
		}
	}
	if extraRole == "unlisted-authority-hold" {
		origin, err := os.ReadFile("../pc2state/testdata/transaction.json")
		if err != nil {
			t.Fatal(err)
		}
		authority, err := pc2state.NewHold("authority", origin)
		if err != nil {
			t.Fatal(err)
		}
		f.proof.Origins = append(f.proof.Origins, digestCensus(origin))
		seeds = append(seeds, nativeSeed{"hold-evidence", "evidence-" + digestBytes(origin) + ".json", origin})
		f.payloads = append(f.payloads, censusPayload{role: "holds", codec: string(pc2state.Hold), raw: authority.Bytes()})
	}
	// Declare PC2 head/guard and optional identical class-inventory copies
	// before any output. Content hashes are not future funding members.
	for i := 0; i < opt.copies; i++ {
		f.payloads = append(f.payloads, censusPayload{role: "inventory", codec: string(pc2state.CapacityInventory), raw: censusWire(t, censusClass{string(pc2state.CapacityInventory), "manager", "staging", []censusRow{}})})
	}
	classPos := len(f.payloads)
	if opt.staging {
		f.payloads = append(f.payloads, censusPayload{role: "inventory", codec: string(pc2state.CapacityInventory), raw: censusWire(t, censusClass{string(pc2state.CapacityInventory), "manager", "staging", []censusRow{}}), staged: true})
		classPos++
	}
	for range 3 {
		f.payloads = append(f.payloads, censusPayload{role: "inventory", codec: string(pc2state.CapacityInventory)})
	}
	invPos := len(f.payloads)
	f.payloads = append(f.payloads, censusPayload{role: "inventory", codec: string(pc2state.ManagerInventory)}, censusPayload{role: "inventory", codec: string(pc2state.RecoveryGuard)})
	allocations := []map[string]any{}
	for i := range f.payloads {
		p := &f.payloads[i]
		p.copyID = fmt.Sprintf("%032x", i+1)
		p.ticket, e = pc2store.TicketID(q, "keymaker", "reservation_metadata", p.role, int64(i+1))
		if e != nil {
			t.Fatal(e)
		}
		allocations = append(allocations, map[string]any{"ticket": p.ticket, "copy_id": p.copyID, "role": p.role, "disposition_version": int64(1), "max_bytes": int64(65536), "integrity_bytes": int64(128), "ordinal": int64(i + 1)})
	}
	if opt.spare {
		id := fmt.Sprintf("%032x", 900)
		ticket, e := pc2store.TicketID(q, "keymaker", "reservation_metadata", "inventory", int64(900))
		if e != nil {
			t.Fatal(e)
		}
		allocations = append(allocations, map[string]any{"ticket": ticket, "copy_id": id, "role": "inventory", "disposition_version": int64(1), "max_bytes": int64(65536), "integrity_bytes": int64(128), "ordinal": int64(900)})
	}
	for i := len(allocations) + len(seeds); i < opt.allocated; i++ {
		ordinal := int64(1000 + i)
		ticket, e := pc2store.TicketID(q, "keymaker", "reservation_metadata", "inventory", ordinal)
		if e != nil {
			t.Fatal(e)
		}
		allocations = append(allocations, map[string]any{"ticket": ticket, "copy_id": fmt.Sprintf("%032x", ordinal), "role": "inventory", "disposition_version": int64(1), "max_bytes": int64(65536), "integrity_bytes": int64(128), "ordinal": ordinal})
	}
	nativeAlloc := []pc2store.NativeAllocation{}
	observations := []pc2store.NativeObservation{}
	nativePrior := map[string]pc2store.NativeObservation{}
	for i, s := range seeds {
		r, _ := pc2store.NativeRoleCatalog(s.role)
		dir := "effects"
		mode := os.FileMode(0600)
		if r.Directory == "native-generations" {
			dir = "generations"
			mode = 0644
		}
		var replaced pc2store.FileImage
		if opt.nativeReplace && s.role == "effects-store" {
			oldBytes, e := effectBytes(priorState)
			if e != nil {
				t.Fatal(e)
			}
			censusWrite(t, filepath.Join(root, dir, s.name), oldBytes, mode)
			replaced, e = c.native[r.Directory].Read(s.name, uint32(mode), r.Cap)
			if e != nil {
				t.Fatal(e)
			}
			censusWrite(t, filepath.Join(root, dir, ".fixture-replacement"), s.raw, mode)
			if e := os.Rename(filepath.Join(root, dir, ".fixture-replacement"), filepath.Join(root, dir, s.name)); e != nil {
				t.Fatal(e)
			}
			censusSyncDir(t, filepath.Join(root, dir))
		} else {
			censusWrite(t, filepath.Join(root, dir, s.name), s.raw, mode)
		}
		image, e := c.native[r.Directory].Read(s.name, uint32(mode), r.Cap)
		if e != nil {
			t.Fatal(e)
		}
		id := fmt.Sprintf("%032x", 100+i)
		allocationRole := s.role
		if s.role == "effects-temporary" {
			allocationRole = "effects-store"
		}
		allocationProfile, _ := pc2store.NativeRoleCatalog(allocationRole)
		ticket, e := pc2store.TicketID(q, "manager", allocationProfile.Class, allocationRole, int64(i+1))
		if e != nil {
			t.Fatal(e)
		}
		nativeAlloc = append(nativeAlloc, pc2store.NativeAllocation{Ticket: ticket, CopyID: id, Role: allocationRole, Ordinal: int64(i + 1), MaxBytes: allocationProfile.Cap, Integrity: 128, SourceOwner: "manager", SourceKind: allocationProfile.Class})
		n := pc2store.NativeObservation{Version: "pc2-native-observation/1", Deployment: strings.Repeat("1", 32), Incarnation: strings.Repeat("2", 32), NativeTicket: ticket, Role: s.role, Directory: r.Directory, Name: s.name, CopyID: id, DispositionVersion: 1, Digest: image.Digest, Bytes: image.Length(), Integrity: 128, Identity: pc2store.NativeIdentity{Device: image.Identity.Device, Inode: image.Identity.Inode, Mount: image.Identity.Mount}, Encoding: r.Encoding}
		switch r.Encoding {
		case "journal":
			n.DispositionVersion = 2
			n.Floor = &pc2store.JournalCheckpoint{Seq: 0, Hash: genjournal.ZeroHash}
			n.Tail = &pc2store.JournalCheckpoint{Seq: 2, Hash: view.Tail.Hash}
		case "effects":
			rev := state.Revision
			n.Revision = &rev
			n.Floor = &pc2store.JournalCheckpoint{Seq: 2, Hash: view.Tail.Hash}
		case "ledger":
			n.Tail = &pc2store.JournalCheckpoint{Seq: 2, Hash: view.Tail.Hash}
		}
		if s.role == "effects-temporary" {
			destination := "effects-store"
			n.Destination, n.Encoding = &destination, "effects"
			staged, err := decodeCensusEffects(s.raw)
			if err != nil {
				t.Fatal(err)
			}
			n.Revision = &staged.Revision
			n.Floor = &pc2store.JournalCheckpoint{Seq: staged.Floor.Seq, Hash: staged.Floor.Hash}
			if opt.nativeRename {
				old := n
				old.StorageID, e = pc2store.StorageID(pc2store.CopyIdentity{Deployment: n.Deployment, Incarnation: n.Incarnation, Owner: "manager", Role: "staging", DirectoryRole: n.Directory, RelativeName: n.Name, CopyID: n.CopyID, DispositionVersion: 1, ContentDigest: n.Digest})
				if e != nil {
					t.Fatal(e)
				}
				nativePrior[id] = old
				n.Role, n.Name, n.Destination, n.DispositionVersion = destination, "evidence-"+digestBytes(s.raw)+".json", nil, 2
				if e := os.Rename(filepath.Join(root, dir, s.name), filepath.Join(root, dir, n.Name)); e != nil {
					t.Fatal(e)
				}
				censusSyncDir(t, filepath.Join(root, dir))
				r = allocationProfile
			}
		}
		if opt.nativeReplace && s.role == "effects-store" {
			old := n
			old.CopyID = fmt.Sprintf("%032x", 8000+i)
			old.NativeTicket, e = pc2store.TicketID(q, "manager", r.Class, s.role, int64(8000+i))
			if e != nil {
				t.Fatal(e)
			}
			old.Bytes, old.Digest, old.Identity = replaced.Length(), replaced.Digest, pc2store.NativeIdentity{Device: replaced.Identity.Device, Inode: replaced.Identity.Inode, Mount: replaced.Identity.Mount}
			revision := priorState.Revision
			old.Revision = &revision
			old.StorageID, e = pc2store.StorageID(pc2store.CopyIdentity{Deployment: old.Deployment, Incarnation: old.Incarnation, Owner: "manager", Role: r.Class, DirectoryRole: old.Directory, RelativeName: old.Name, CopyID: old.CopyID, DispositionVersion: 1, ContentDigest: old.Digest})
			if e != nil {
				t.Fatal(e)
			}
			nativeAlloc = append(nativeAlloc, pc2store.NativeAllocation{Ticket: old.NativeTicket, CopyID: old.CopyID, Role: s.role, Ordinal: int64(8000 + i), MaxBytes: r.Cap, Integrity: 128, SourceOwner: "manager", SourceKind: r.Class})
			nativePrior[id] = old
		}
		n.StorageID, e = pc2store.StorageID(pc2store.CopyIdentity{Deployment: n.Deployment, Incarnation: n.Incarnation, Owner: "manager", Role: r.Class, DirectoryRole: n.Directory, RelativeName: n.Name, CopyID: id, DispositionVersion: n.DispositionVersion, ContentDigest: n.Digest})
		if e != nil {
			t.Fatal(e)
		}
		observations = append(observations, n)
	}
	outputs := []pc2store.CensusOutput{}
	bound := opt.outputBound
	if bound == 0 {
		bound = 65536
	}
	for i, k := range append(censusClasses[:], "head") {
		outputBound := bound
		if k == "head" && headBound > 0 {
			outputBound = headBound
		}
		outputs = append(outputs, pc2store.CensusOutput{Kind: k, Ordinal: int64(i + 1), MaxBytes: outputBound, Integrity: 128})
	}
	metadata := int64(8 * 1024 * 1024)
	if opt.history {
		metadata = 16 * 1024 * 1024
	} // Original reserve covers the larger retained index frontier.
	funding := censusWire(t, map[string]any{"version": "pc2-native-fixture-funding/1", "deployment": strings.Repeat("1", 32), "incarnation": strings.Repeat("2", 32), "q": q, "metadata_bytes": metadata, "metadata_integrity": int64(256), "allocations": allocations, "native_allocations": nativeAlloc, "census_outputs": outputs})
	fundingD := digestCensus(funding)
	classRows := map[string][]censusRow{"attempts": {}, "holds": {}, "recovery": {}}
	for _, n := range observations {
		r, _ := pc2store.NativeRoleCatalog(n.Role)
		if _, ok := classRows[r.Class]; ok {
			classRows[r.Class] = append(classRows[r.Class], censusRow{n.StorageID, n.Bytes, n.Integrity})
		}
	}
	for _, p := range f.payloads[:invPos] {
		if _, ok := classRows[p.role]; ok {
			id, e := pc2store.StorageID(pc2store.CopyIdentity{Deployment: strings.Repeat("1", 32), Incarnation: strings.Repeat("2", 32), Owner: "manager", Role: p.role, DirectoryRole: p.role, RelativeName: p.role + "/" + p.copyID + "/" + digestBytes(p.raw) + ".json", CopyID: p.copyID, DispositionVersion: 1, ContentDigest: digestCensus(p.raw)})
			if e != nil {
				t.Fatal(e)
			}
			classRows[p.role] = append(classRows[p.role], censusRow{id, int64(len(p.raw)), 128})
		}
	}
	classDigests := map[string]string{}
	var materialized, objects int64
	for classIndex, k := range []string{"attempts", "holds", "recovery"} {
		rows := classRows[k]
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		classRaw := censusWire(t, censusClass{string(pc2state.CapacityInventory), "manager", k, rows})
		f.payloads[classPos+classIndex].raw = classRaw
		classDigests[k] = digestCensus(classRaw)
		for _, r := range rows {
			materialized += r.Bytes
			objects++
		}
	}
	inventory := censusWire(t, map[string]any{"version": string(pc2state.ManagerInventory), "revision": int64(1), "previous_digest": nil, "attempts_digest": classDigests["attempts"], "holds_digest": classDigests["holds"], "recovery_digest": classDigests["recovery"], "materialized_bytes": materialized, "objects": objects, "slot_reservation": q})
	f.payloads[invPos].raw = inventory
	guard := map[string]any{"version": string(pc2state.RecoveryGuard), "revision": int64(1), "previous_digest": nil, "inventory": map[string]any{"codec": string(pc2state.ManagerInventory), "digest": digestCensus(inventory), "bytes": int64(len(inventory))}, "phase": "clear", "holds": []any{}, "attempt": nil, "resolution": nil, "release_prepared": nil, "released": nil, "source_root_digest": digestCensus(rootRaw)}
	if opt.occupied || opt.authority {
		hm, _ := treeCensus(hold.Bytes())
		guard["phase"] = "open"
		guard["holds"] = []any{map[string]any{"kind": hm["kind"], "origin_id": hm["origin_id"], "hold_id": digestCensus(hold.Bytes())}}
		if opt.occupied && !opt.authority {
			guard["attempt"] = map[string]any{"codec": string(pc2state.ActivationAttempt), "digest": digestCensus(attempt.Bytes()), "bytes": int64(len(attempt.Bytes()))}
		}
	}
	f.payloads[invPos+1].raw = censusWire(t, guard)
	idx := filepath.Join(root, "pc2/inventory/owner-index")
	censusWrite(t, filepath.Join(idx, "funding.json"), funding, 0640)
	censusWrite(t, filepath.Join(idx, "writer.lock"), nil, 0640)
	genesis := censusWire(t, map[string]any{"version": "pc2-owner-transition/1", "sequence": int64(0), "previous": "", "event": "genesis", "ticket": "", "content_digest": "", "bytes": int64(0), "codec": "", "from": "", "to": "", "storage_id": "", "identity": map[string]any{"device": int64(0), "inode": int64(0), "mount": int64(0)}})
	head := pc2store.Head{Sequence: 0, Digest: digestCensus(genesis)}
	genesisD := head.Digest
	appendRecord := func(raw []byte) {
		censusWrite(t, filepath.Join(idx, "records", digestBytes(raw)+".json"), raw, 0640)
		hraw := censusWire(t, head)
		censusWrite(t, filepath.Join(idx, "heads", digestBytes(hraw)+".json"), hraw, 0640)
	}
	appendRecord(genesis)
	for i := range f.payloads {
		p := &f.payloads[i]
		censusDir(t, filepath.Join(root, "pc2/staging", p.copyID), 0750)
		censusDir(t, filepath.Join(root, "pc2", p.role, p.copyID), 0750)
		name := digestBytes(p.raw) + ".json"
		physicalRole := p.role
		if p.staged {
			physicalRole = "staging"
		}
		censusWrite(t, filepath.Join(root, "pc2", physicalRole, p.copyID, name), p.raw, 0640)
		d := censusChild(t, censusChild(t, c.pc2, physicalRole), p.copyID)
		image, e := d.Read(name, 0640, 65536)
		if e != nil {
			t.Fatal(e)
		}
		p.identity = image.Identity
		rec := map[string]any{"version": "pc2-owner-transition/1", "sequence": head.Sequence + 1, "previous": head.Digest, "event": "associate", "ticket": p.ticket, "content_digest": digestCensus(p.raw), "bytes": int64(len(p.raw)), "codec": p.codec, "from": "", "to": "staging/" + p.copyID + "/" + name, "storage_id": "", "identity": map[string]any{"device": int64(0), "inode": int64(0), "mount": int64(0)}}
		raw := censusWire(t, rec)
		head = pc2store.Head{Sequence: head.Sequence + 1, Digest: digestCensus(raw)}
		p.order = head.Sequence
		appendRecord(raw)
		if p.staged {
			continue
		}
		rec["sequence"] = head.Sequence + 1
		rec["previous"] = head.Digest
		rec["event"] = "install"
		rec["from"] = rec["to"]
		rec["to"] = p.role + "/" + p.copyID + "/" + name
		rec["identity"] = map[string]any{"device": int64(image.Identity.Device), "inode": int64(image.Identity.Inode), "mount": int64(image.Identity.Mount)}
		sid, e := pc2store.StorageID(pc2store.CopyIdentity{Deployment: strings.Repeat("1", 32), Incarnation: strings.Repeat("2", 32), Owner: "manager", Role: p.role, DirectoryRole: p.role, RelativeName: rec["to"].(string), CopyID: p.copyID, DispositionVersion: 1, ContentDigest: digestCensus(p.raw)})
		if e != nil {
			t.Fatal(e)
		}
		rec["storage_id"] = sid
		raw = censusWire(t, rec)
		head = pc2store.Head{Sequence: head.Sequence + 1, Digest: digestCensus(raw)}
		appendRecord(raw)
		if i == invPos {
			c.targets = append(c.targets, pc2store.HeadTarget{Directory: auth, Name: "root.json", Cap: 1048576}, pc2store.HeadTarget{}, pc2store.HeadTarget{Directory: d, Name: name, Cap: 65536})
		}
		if i == invPos+1 {
			c.targets[1] = pc2store.HeadTarget{Directory: d, Name: name, Cap: 65536}
		}
	}
	for _, n := range observations {
		if old, ok := nativePrior[n.CopyID]; ok {
			old.FundingDigest, old.Sequence, old.Previous = fundingD, head.Sequence+1, head.Digest
			raw := censusWire(t, old)
			if _, e := pc2store.DecodeNativeObservation(raw); e != nil {
				t.Fatal("prior native observation", e)
			}
			head = pc2store.Head{Sequence: old.Sequence, Digest: digestCensus(raw)}
			appendRecord(raw)
			f.native = append(f.native, old)
			prior := head.Digest
			if old.CopyID == n.CopyID {
				n.Prior = &prior
			} else {
				n.Replaces = &prior
			}
		}
		if n.Role == "generation-journal" {
			old := n
			old.DispositionVersion = 1
			old.Bytes = int64(len(first))
			old.Digest = digestCensus(first)
			old.Tail = &pc2store.JournalCheckpoint{Seq: 1, Hash: genjournal.Digest(first)}
			old.FundingDigest = fundingD
			old.Sequence = head.Sequence + 1
			old.Previous = head.Digest
			old.StorageID, e = pc2store.StorageID(pc2store.CopyIdentity{Deployment: old.Deployment, Incarnation: old.Incarnation, Owner: "manager", Role: "recovery", DirectoryRole: old.Directory, RelativeName: old.Name, CopyID: old.CopyID, DispositionVersion: 1, ContentDigest: old.Digest})
			if e != nil {
				t.Fatal(e)
			}
			raw := censusWire(t, old)
			head = pc2store.Head{Sequence: old.Sequence, Digest: digestCensus(raw)}
			appendRecord(raw)
			f.native = append(f.native, old)
			prior := head.Digest
			n.Prior = &prior
		}
		n.FundingDigest = fundingD
		n.Sequence = head.Sequence + 1
		n.Previous = head.Digest
		raw := censusWire(t, n)
		if _, e := pc2store.DecodeNativeObservation(raw); e != nil {
			t.Fatal("observation", e)
		}
		head = pc2store.Head{Sequence: n.Sequence, Digest: digestCensus(raw)}
		appendRecord(raw)
		f.native = append(f.native, n)
	}
	censusWrite(t, filepath.Join(idx, "head.json"), censusWire(t, head), 0640)
	c.targets = append(c.targets, pc2store.HeadTarget{Directory: auth, Name: "floor.json", Cap: 8192}, pc2store.HeadTarget{Directory: auth, Name: "intent.json", Cap: 8192})
	c.baseline = pc2store.SnapshotBaseline{Profile: "pc2-native-owner-index/1", FundingDigest: fundingD, Genesis: genesisD, Head: head}
	f.proof.Index = head
	f.proof.Funding = fundingD
	f.proof.Genesis = genesisD
	for _, target := range c.targets {
		image, e := target.Directory.Read(target.Name, 0640, target.Cap)
		if e != nil {
			t.Fatal(e)
		}
		f.proof.Heads = append(f.proof.Heads, image.Digest)
	}
	f.bind(t)
	return f
}

// Claim: schema lines 523-529 admit a complete funded effects temporary while
// the installed predecessor remains. Identical-state and next-revision copies
// both have complete bytes, logical proofs and closure; preparation writes none.
func TestReviewQ2S3StagedEffects(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		t.Run(fmt.Sprintf("advanced=%v", advanced), func(t *testing.T) {
			f := reviewNativeStageFixture(t, censusOptions{nativeStage: true}, advanced, "", 0)
			before := censusTreeBytes(t, f.root)
			snap, err := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
			if err != nil {
				t.Fatal("snapshot prerequisite", err)
			}
			images := []nativeCensusImage{}
			for _, n := range snap.Native() {
				im, err := readCensusNative(f.c.native[n.Directory], n)
				if err != nil {
					t.Fatal("native byte prerequisite", err)
				}
				images = append(images, im)
			}
			t.Log("complete indexed snapshot and all native byte parsers accepted", len(images))
			p, err := prepareManagerCensus(f.c)
			censusSameTree(t, before, censusTreeBytes(t, f.root))
			if err != nil || p == nil {
				t.Fatalf("complete registered effects temporary refused: advanced=%v history=%v preparation=%v", advanced, censusNativeHistory(images, snap.History(), f.proof.Effects), err)
			}
			if len(decodePreparedClass(t, p, "staging").Objects) != 1 {
				t.Fatal("staged physical copy missing")
			}
		})
	}
}

// Claim: spec 531-535 requires retained immutable origin/evidence links before
// specific attempt/hold attribution. A funded recovery evidence control passes;
// merely funding the same JSON under a specific role must not create that link.
func TestReviewQ2S3SpecificEvidenceLinks(t *testing.T) {
	for _, role := range []string{"recovery-evidence", "attempt-evidence", "hold-evidence"} {
		t.Run(role, func(t *testing.T) {
			f := reviewNativeStageFixture(t, censusOptions{}, false, role, 0)
			before := censusTreeBytes(t, f.root)
			snap, err := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
			if err != nil {
				t.Fatal("complete snapshot prerequisite", err)
			}
			for _, n := range snap.Native() {
				if _, err := readCensusNative(f.c.native[n.Directory], n); err != nil {
					t.Fatal("complete native bytes prerequisite", err)
				}
			}
			p, err := prepareManagerCensus(f.c)
			censusSameTree(t, before, censusTreeBytes(t, f.root))
			if role == "recovery-evidence" {
				if p == nil || err != nil {
					t.Fatal("valid recovery control", err)
				}
				return
			}
			if p != nil || !errors.Is(err, ErrCensusUnavailable) {
				v, owner := p.Slot()
				t.Fatalf("specific native evidence without any attempt/hold/origin accepted: role=%s slot=%s owner=%q err=%v", role, v, owner, err)
			}
		})
	}
}

// Claim: with every other output fully funded, the exact prospective head byte
// limit accepts and one byte less refuses without effects. This does not measure
// native allocation overhead or qualify a future publisher.
func TestReviewQ2S3HeadOutputBoundary(t *testing.T) {
	base := reviewNativeStageFixture(t, censusOptions{}, false, "", 0)
	required := int64(len(censusValid(t, base.c).HeadBytes()))
	for _, cap := range []int64{required, required - 1} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			f := reviewNativeStageFixture(t, censusOptions{}, false, "", cap)
			before := censusTreeBytes(t, f.root)
			p, err := prepareManagerCensus(f.c)
			censusSameTree(t, before, censusTreeBytes(t, f.root))
			if cap == required {
				if err != nil || p == nil || int64(len(p.HeadBytes())) != required {
					t.Fatal("exact encoded head cap refused", required, err)
				}
			} else {
				if p != nil || !errors.Is(err, ErrCensusUnavailable) {
					t.Fatal("head cap+1 accepted", err)
				}
			}
		})
	}
}

// Claim: an independently linked retained authority hold vetoes an occupied
// activation even when a well-formed guard omits it. The original single-owner
// fixture is the positive control; preparation must preserve every retained file.
func TestReviewQ2S3UnlistedAuthorityHold(t *testing.T) {
	censusValid(t, newCensusFixture(t, censusOptions{occupied: true}).c)
	f := reviewNativeStageFixture(t, censusOptions{occupied: true}, false, "unlisted-authority-hold", 0)
	snap, err := pc2store.ReadSnapshot(f.c.pc2, f.c.baseline)
	if err != nil {
		t.Fatal("funded indexed fixture prerequisite", err)
	}
	count := 0
	for _, entry := range snap.Entries() {
		if entry.Codec == string(pc2state.Hold) {
			count++
		}
	}
	if count != 2 {
		t.Fatal("authority hold witness missing", count)
	}
	before := censusTreeBytes(t, f.root)
	p, err := prepareManagerCensus(f.c)
	censusSameTree(t, before, censusTreeBytes(t, f.root))
	if p != nil || !errors.Is(err, ErrCensusUnavailable) {
		v, owner := p.Slot()
		t.Fatalf("retained authority hold omitted by guard did not veto: verdict=%s owner=%s err=%v", v, owner, err)
	}
}
