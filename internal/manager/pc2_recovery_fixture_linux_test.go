//go:build linux

package manager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
	"github.com/relux-works/swarma-user-manager/internal/pc2store"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// All authority, exclusion, original funding and provisioning are fixtures.
// This does not install a coordinator, provide verity or qualify actual readers.
type recoveryFixture struct {
	root                                   string
	pc2, auth, effects, generations, fence *pc2store.ReadDirectory
	c                                      recoveryContext
	base                                   pc2store.SnapshotBaseline
	outputs                                []pc2store.RecoveryOutput
	locations                              []string
}

func recoveryObject(t *testing.T, k pc2state.Kind, m any) pc2state.Object {
	t.Helper()
	o, e := pc2state.Decode(k, censusWire(t, m))
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func recoveryRef(o pc2state.Object) map[string]any {
	return map[string]any{"codec": string(o.Kind()), "digest": digestCensus(o.Bytes()), "bytes": int64(len(o.Bytes()))}
}
func recoveryPin(t *testing.T, d *pc2store.ReadDirectory, name string, mode uint32, cap int64) *pc2store.RecoveryFile {
	t.Helper()
	p, e := d.PinRecoveryFile(name, mode, cap)
	if e != nil {
		t.Fatal(name, e)
	}
	t.Cleanup(func() {
		if e := p.Close(); e != nil {
			t.Error(e)
		}
	})
	return p
}
func recoveryPathPin(t *testing.T, root *pc2store.ReadDirectory, rel string) *pc2store.RecoveryFile {
	t.Helper()
	parts := strings.Split(rel, "/")
	d := root
	for _, s := range parts[:len(parts)-1] {
		d = censusChild(t, d, s)
	}
	return recoveryPin(t, d, parts[len(parts)-1], 0640, 65536)
}
func newRecoveryFixture(t *testing.T, disposition string, extra ...pc2state.Object) *recoveryFixture {
	return newRecoveryFixtureKind(t, disposition, "activation", extra...)
}
func newRecoveryFixtureKind(t *testing.T, disposition, kind string, extra ...pc2state.Object) *recoveryFixture {
	t.Helper()
	root := t.TempDir()
	censusDir(t, root, 0700)
	for _, rel := range []string{"pc2", "pc2/attempts", "pc2/holds", "pc2/recovery", "pc2/inventory", "pc2/capacity", "pc2/staging", "pc2/inventory/owner-index", "pc2/inventory/owner-index/records", "pc2/inventory/owner-index/heads", "pc2/inventory/owner-index/pending", "auth", "fence"} {
		censusDir(t, filepath.Join(root, rel), 0750)
	}
	censusDir(t, filepath.Join(root, "effects"), 0700)
	censusDir(t, filepath.Join(root, "generations"), 0755)
	parent, e := os.Open(root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := parent.Close(); e != nil {
			t.Error(e)
		}
	})
	f := &recoveryFixture{root: root, pc2: censusPin(t, parent, "pc2", 0750), auth: censusPin(t, parent, "auth", 0750), effects: censusPin(t, parent, "effects", 0700), generations: censusPin(t, parent, "generations", 0755), fence: censusPin(t, parent, "fence", 0750)}
	for rel, mode := range map[string]os.FileMode{"effects/effects.lock": 0600, "generations/gate.lock": 0644, "generations/data.lock": 0644, "fence/authority.lock": 0640} {
		censusWrite(t, filepath.Join(root, rel), nil, mode)
	}
	rootRaw := censusWire(t, map[string]any{"fixture": "independently-held-root", "revision": int64(1)})
	floorRaw := censusWire(t, map[string]any{"fixture": "independent-floor-3", "root": digestCensus(rootRaw)})
	intentRaw := censusWire(t, map[string]any{"fixture": "original-clear-intent", "transaction": strings.Repeat("a", 64)})
	for name, raw := range map[string][]byte{"root.json": rootRaw, "floor.json": floorRaw, "intent.json": intentRaw} {
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
	journal := append([]byte(nil), first...)
	if disposition == "durable" {
		journal = append(journal, second...)
	}
	censusWrite(t, filepath.Join(root, "generations/journal"), journal, 0644)
	censusWrite(t, filepath.Join(root, "generations/writer.pending"), []byte("fixture-exact-owned-marker"), 0644)
	original := censusWire(t, map[string]any{"fixture": "original-effect-intent", "owner": "owner"})
	pre, e := os.ReadFile("../pc2state/testdata/attempt-preimage.json")
	if e != nil {
		t.Fatal(e)
	}
	pm, _ := treeCensus(pre)
	pm["manager_id"] = strings.Repeat("1", 32)
	pm["effect_digest"] = digestCensus(original)
	pm["prepared_tail"] = map[string]any{"seq": int64(1), "hash": genjournal.Digest(first)}
	pm["active_record_hash"] = genjournal.Digest(second)
	pm["target"].(map[string]any)["uid"] = int64(10)
	pm["target"].(map[string]any)["generation"] = strings.Repeat("1", 32)
	pm["source"].(map[string]any)["root_digest"] = digestCensus(rootRaw)
	pre = censusWire(t, pm)
	pending, e := pc2state.NewPendingAttempt(pre)
	if e != nil {
		t.Fatal(e)
	}
	hold, e := pc2state.NewHold("activation", pre)
	if e != nil {
		t.Fatal(e)
	}
	if kind == "authority" {
		pre, e = os.ReadFile("../pc2state/testdata/transaction.json")
		if e != nil {
			t.Fatal(e)
		}
		hold, e = pc2state.NewHold("authority", pre)
		if e != nil {
			t.Fatal(e)
		}
	}
	id := strings.Repeat("3", 32)
	hd := digestCensus(hold.Bytes())
	view, e := genjournal.Verify(strings.NewReader(string(journal)), genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	proof := censusWire(t, map[string]any{"fixture": "retained-owner-outcome", "session": id, "hold": hd, "outcome": disposition, "journal": view.Tail, "exclusion": "independent-owned-fixture"})
	am, _ := treeCensus(pending.Bytes())
	am["disposition"] = disposition
	am["evidence_digest"] = digestCensus(proof)
	attempt := recoveryObject(t, pc2state.ActivationAttempt, am)
	invRaw, e := os.ReadFile("../pc2state/testdata/manager-inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	inventory, e := pc2state.Decode(pc2state.ManagerInventory, invRaw)
	if e != nil {
		t.Fatal(e)
	}
	storedAttempt := attempt
	if kind == "authority" {
		attempt = pc2state.Object{}
		storedAttempt = recoveryObject(t, pc2state.CapacityInventory, censusClass{Version: string(pc2state.CapacityInventory), Owner: "manager", Kind: "attempts", Objects: []censusRow{}})
	}
	cl := recoveryClosure{hold: hold, attempt: attempt, origin: string(pre), objects: map[string]pc2state.Object{}, evidence: map[string]string{digestCensus(proof): string(proof)}}
	for _, o := range []pc2state.Object{storedAttempt, hold, inventory} {
		cl.objects[digestCensus(o.Bytes())] = o
	}
	outcome := genjournal.DurableCleanupUncertain
	if disposition == "absent" {
		outcome = genjournal.NoWrite
	}
	cl.accepted = recoveryAccepted{id: id, hold: hd, root: digestCensus(rootRaw), floor: digestCensus(floorRaw), intent: digestCensus(intentRaw), inventory: digestCensus(invRaw), proof: digestCensus(proof), marker: digestCensus([]byte("fixture-exact-owned-marker")), origin: digestCensus(pre), exclusion: "independent-owned-fixture", outcome: outcome, disposition: disposition, checkpoint: view.Tail, journal: string(journal), originalIntent: string(original)}
	hm, _ := treeCensus(hold.Bytes())
	guardMap := map[string]any{"version": string(pc2state.RecoveryGuard), "revision": int64(1), "previous_digest": nil, "inventory": recoveryRef(inventory), "phase": "open", "holds": []any{map[string]any{"kind": hm["kind"], "origin_id": hm["origin_id"], "hold_id": hd}}, "attempt": recoveryRef(attempt), "resolution": nil, "release_prepared": nil, "released": nil, "source_root_digest": cl.accepted.root}
	if kind == "authority" {
		guardMap["attempt"] = nil
	}
	initial := recoveryObject(t, pc2state.RecoveryGuard, guardMap)
	censusWrite(t, filepath.Join(root, "auth/guard.json"), initial.Bytes(), 0640)
	var prev any
	for i, phase := range []string{"open", "resolved", "release-prepared", "released"} {
		result := "unknown"
		var evidence any
		cp := genjournal.Floor{Seq: 1, Hash: genjournal.Digest(first)}
		if i > 0 {
			result = disposition
			evidence = cl.accepted.proof
			cp = view.Tail
		}
		record := recoveryObject(t, pc2state.RecoveryRecord, map[string]any{"version": string(pc2state.RecoveryRecord), "recovery_id": id, "previous_digest": prev, "phase": phase, "holds": []any{hd}, "root_digest": cl.accepted.root, "journal": cp, "outcome": result, "evidence_digest": evidence})
		cl.records = append(cl.records, record)
		cl.objects[digestCensus(record.Bytes())] = record
		prev = digestCensus(record.Bytes())
		guardMap["revision"] = int64(i + 2)
		guardMap["previous_digest"] = digestCensus(initial.Bytes())
		if i > 0 {
			guardMap["previous_digest"] = digestCensus(cl.guards[i-1].Bytes())
		}
		guardMap["phase"] = phase
		if i > 0 {
			guardMap[[]string{"resolution", "release_prepared", "released"}[i-1]] = recoveryRef(record)
		}
		cl.guards = append(cl.guards, recoveryObject(t, pc2state.RecoveryGuard, guardMap))
	}
	f.c = recoveryContext{closure: cl, markerParent: f.generations, guardParent: f.auth}
	f.installFunding(t, append([]pc2state.Object{storedAttempt, hold, inventory}, extra...))
	f.refresh(t)
	return f
}

func (f *recoveryFixture) installFunding(t *testing.T, initial []pc2state.Object) {
	t.Helper()
	alloc := []map[string]any{}
	all := append([]pc2state.Object(nil), initial...)
	for i := range 4 {
		all = append(all, f.c.closure.records[i], f.c.closure.guards[i])
	}
	q := "sha256:" + strings.Repeat("a", 64)
	for i, o := range all {
		role := "inventory"
		if o.Kind() == pc2state.ActivationAttempt {
			role = "attempts"
		}
		if o.Kind() == pc2state.Hold {
			role = "holds"
		}
		if o.Kind() == pc2state.RecoveryRecord {
			role = "recovery"
		}
		ticket, e := pc2store.TicketID(q, "keymaker", "reservation_metadata", role, int64(i+1))
		if e != nil {
			t.Fatal(e)
		}
		id := fmt.Sprintf("%032x", i+1)
		alloc = append(alloc, map[string]any{"ticket": ticket, "copy_id": id, "role": role, "disposition_version": int64(1), "max_bytes": int64(65536), "integrity_bytes": int64(128), "ordinal": int64(i + 1)})
		if i >= len(initial) {
			f.outputs = append(f.outputs, pc2store.RecoveryOutput{Ticket: ticket, Object: o})
		}
		f.locations = append(f.locations, role+"/"+id+"/"+digestBytes(o.Bytes())+".json")
	}
	funding := censusWire(t, map[string]any{"version": "pc2-fixture-funding/1", "deployment": strings.Repeat("1", 32), "incarnation": strings.Repeat("2", 32), "q": q, "metadata_bytes": int64(8 * 1024 * 1024), "allocations": alloc})
	idx := filepath.Join(f.root, "pc2/inventory/owner-index")
	censusWrite(t, filepath.Join(idx, "funding.json"), funding, 0640)
	censusWrite(t, filepath.Join(idx, "writer.lock"), nil, 0640)
	zero := map[string]any{"version": "pc2-owner-transition/1", "sequence": int64(0), "previous": "", "event": "genesis", "ticket": "", "content_digest": "", "bytes": int64(0), "codec": "", "from": "", "to": "", "storage_id": "", "identity": map[string]any{"device": int64(0), "inode": int64(0), "mount": int64(0)}}
	raw := censusWire(t, zero)
	head := pc2store.Head{Sequence: 0, Digest: digestCensus(raw)}
	genesis := head.Digest
	appendRecord := func(raw []byte) {
		censusWrite(t, filepath.Join(idx, "records", digestBytes(raw)+".json"), raw, 0640)
		hb := censusWire(t, head)
		censusWrite(t, filepath.Join(idx, "heads", digestBytes(hb)+".json"), hb, 0640)
	}
	appendRecord(raw)
	for i, o := range initial {
		a := alloc[i]
		role := a["role"].(string)
		id := a["copy_id"].(string)
		loc := f.locations[i]
		censusDir(t, filepath.Join(f.root, "pc2/staging", id), 0750)
		censusDir(t, filepath.Join(f.root, "pc2", role, id), 0750)
		censusWrite(t, filepath.Join(f.root, "pc2", loc), o.Bytes(), 0640)
		image, e := recoveryPathRead(t, f.pc2, loc)
		if e != nil {
			t.Fatal(e)
		}
		sid, e := pc2store.StorageID(pc2store.CopyIdentity{Deployment: strings.Repeat("1", 32), Incarnation: strings.Repeat("2", 32), Owner: "manager", Role: role, DirectoryRole: role, RelativeName: loc, CopyID: id, DispositionVersion: 1, ContentDigest: image.Digest})
		if e != nil {
			t.Fatal(e)
		}
		for _, event := range []string{"associate", "install"} {
			from := ""
			to := "staging/" + id + "/" + digestBytes(o.Bytes()) + ".json"
			storage := ""
			identity := pc2store.FileIdentity{}
			if event == "install" {
				from = to
				to = loc
				storage = sid
				identity = image.Identity
			}
			raw = censusWire(t, map[string]any{"version": "pc2-owner-transition/1", "sequence": head.Sequence + 1, "previous": head.Digest, "event": event, "ticket": a["ticket"], "content_digest": image.Digest, "bytes": image.Length(), "codec": string(o.Kind()), "from": from, "to": to, "storage_id": storage, "identity": map[string]any{"device": identity.Device, "inode": identity.Inode, "mount": identity.Mount}})
			head = pc2store.Head{Sequence: head.Sequence + 1, Digest: digestCensus(raw)}
			appendRecord(raw)
		}
	}
	censusWrite(t, filepath.Join(idx, "head.json"), censusWire(t, head), 0640)
	f.base = pc2store.SnapshotBaseline{Profile: "pc2-recovery-fixture/1", FundingDigest: digestCensus(funding), Genesis: genesis, Head: head}
}
func recoveryPathRead(t *testing.T, root *pc2store.ReadDirectory, rel string) (pc2store.FileImage, error) {
	t.Helper()
	p := recoveryPathPin(t, root, rel)
	return p.Image(), nil
}
func (f *recoveryFixture) refresh(t *testing.T) {
	t.Helper()
	hb, e := os.ReadFile(filepath.Join(f.root, "pc2/inventory/owner-index/head.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strict(hb, &f.base.Head) != nil {
		t.Fatal("head")
	}
	batch, e := pc2store.PrepareRecoveryOutputs(f.pc2, f.base, f.outputs)
	if e != nil {
		t.Fatal("prepare batch", e)
	}
	f.c.batch = batch
	f.c.guard, e = f.auth.Read("guard.json", 0640, 65536)
	if e != nil {
		t.Fatal(e)
	}
	f.c.heads = nil
	for _, name := range []string{"root.json", "floor.json", "intent.json"} {
		f.c.heads = append(f.c.heads, recoveryHead{recoveryPin(t, f.auth, name, 0640, 1048576), 1048576})
	}
	f.c.locks = []*pc2store.RecoveryFile{recoveryPin(t, f.effects, "effects.lock", 0600, 0), recoveryPin(t, f.generations, "gate.lock", 0644, 0), recoveryPin(t, f.generations, "data.lock", 0644, 0)}
	f.c.repairs = []*pc2store.RecoveryFile{recoveryPin(t, f.generations, "journal", 0644, genjournal.MaxFile)}
	f.c.repairParents = []*pc2store.ReadDirectory{f.generations}
	f.c.marker = nil
	if _, e := os.Stat(filepath.Join(f.root, "generations/writer.pending")); e == nil {
		f.c.marker = recoveryPin(t, f.generations, "writer.pending", 0644, 4096)
	} else if !os.IsNotExist(e) {
		t.Fatal(e)
	}
	lock := recoveryPin(t, f.fence, "authority.lock", 0640, 0)
	f.c.fence, e = f.fence.PrepareRecoveryFence(lock.Image().Identity, time.Now().Add(120*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	w := f.c.fence
	t.Cleanup(func() {
		if e := w.Close(); e != nil {
			t.Error(e)
		}
	})
}
func (f *recoveryFixture) run(t *testing.T) {
	t.Helper()
	p, e := prepareRecovery(&f.c)
	if e != nil {
		t.Fatal("prepare", e)
	}
	r, e := executeRecovery(context.Background(), p)
	if e != nil || r.ID != f.c.closure.accepted.id || r.Phase != "released" {
		t.Fatal("execute", r, e)
	}
}

func (f *recoveryFixture) releaseContext(t *testing.T) recoveryReleaseContext {
	t.Helper()
	f.refresh(t)
	c := recoveryReleaseContext{batch: f.c.batch, closure: f.c.closure, cleanup: f.generations, fence: f.c.fence, locks: f.c.locks}
	names := map[string]string{"root": "root.json", "guard": "guard.json", "floor": "floor.json", "intent": "intent.json"}
	for i, role := range releaseMetadataRoles {
		var pin *pc2store.RecoveryFile
		if name := names[role]; name != "" {
			pin = recoveryPin(t, f.auth, name, 0640, releaseMetadataCaps[i])
		} else {
			loc := ""
			switch role {
			case "inventory":
				loc = f.locations[2]
			case "attempt":
				if f.c.closure.attempt.Kind() == "" {
					c.metadata = append(c.metadata, releaseFile{role, nil})
					continue
				}
				loc = f.locations[0]
			case "resolution":
				loc = f.locations[5]
			case "release-prepared":
				loc = f.locations[7]
			case "released":
				loc = f.locations[9]
			}
			if loc != "" {
				pin = recoveryPathPin(t, f.pc2, loc)
			} else {
				name = role + ".json"
				censusWrite(t, filepath.Join(f.root, "auth", name), censusWire(t, map[string]any{"fixture": "prepared-" + role}), 0640)
				pin = recoveryPin(t, f.auth, name, 0640, releaseMetadataCaps[i])
			}
		}
		c.metadata = append(c.metadata, releaseFile{role, pin})
	}
	for _, role := range releaseParticipantRoles {
		name := "participant-" + role + ".json"
		censusWrite(t, filepath.Join(f.root, "auth", name), censusWire(t, map[string]any{"fixture": "sealed-role-" + role}), 0640)
		c.participants = append(c.participants, releaseFile{role, recoveryPin(t, f.auth, name, 0640, 65536)})
	}
	recoveryDir := censusChild(t, f.pc2, "recovery")
	c.ledger = censusChild(t, recoveryDir, strings.Split(f.locations[9], "/")[1])
	c.parents = []*pc2store.ReadDirectory{f.pc2, f.auth, f.generations}
	return c
}
