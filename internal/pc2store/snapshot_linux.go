//go:build linux

package pc2store

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

func unmarshalTraversal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// SnapshotBaseline is an exact external commitment, not a local high-water
// discovery policy. ReadSnapshot only checks mechanics against these bytes;
// it does not authenticate the provider or issue a verified credit capability.
type SnapshotBaseline struct {
	Profile, FundingDigest, Genesis string
	Head                            Head
}

type NativeAllocation struct {
	Ticket      string `json:"ticket"`
	CopyID      string `json:"copy_id"`
	Role        string `json:"role"`
	Ordinal     int64  `json:"ordinal"`
	MaxBytes    int64  `json:"max_bytes"`
	Integrity   int64  `json:"integrity_bytes"`
	SourceOwner string `json:"source_owner"`
	SourceKind  string `json:"source_kind"`
}
type nativeFunding struct {
	Version           string             `json:"version"`
	Deployment        string             `json:"deployment"`
	Incarnation       string             `json:"incarnation"`
	Q                 string             `json:"q"`
	Metadata          int64              `json:"metadata_bytes"`
	MetadataIntegrity int64              `json:"metadata_integrity"`
	Allocations       []allocation       `json:"allocations"`
	Native            []NativeAllocation `json:"native_allocations"`
}

type SnapshotEntry struct {
	ID, Class, Location, Codec string
	Image                      FileImage
	Integrity                  int64
}
type ReadSnapshotResult struct {
	head            Head
	entries         []SnapshotEntry
	native, history []NativeObservation
	held, envelope  int64
	q               string
}

func (s ReadSnapshotResult) Entries() []SnapshotEntry {
	return append([]SnapshotEntry(nil), s.entries...)
}
func (s ReadSnapshotResult) Native() []NativeObservation {
	out := make([]NativeObservation, len(s.native))
	for i, n := range s.native {
		out[i] = cloneNative(n)
	}
	return out
}
func (s ReadSnapshotResult) History() []NativeObservation {
	out := make([]NativeObservation, len(s.history))
	for i, n := range s.history {
		out[i] = cloneNative(n)
	}
	return out
}
func (s ReadSnapshotResult) HeldBytes() int64    { return s.held }
func (s ReadSnapshotResult) Envelope() int64     { return s.envelope }
func (s ReadSnapshotResult) Reservation() string { return s.q }

func readPath(root *ReadDirectory, rel string, cap int64) (out FileImage, err error) {
	if !relative(rel) {
		return out, ErrUnavailable
	}
	parts := strings.Split(rel, "/")
	d := root
	var owned []*ReadDirectory
	defer func() {
		for i := len(owned) - 1; i >= 0; i-- {
			err = errors.Join(err, owned[i].Close())
		}
		if err != nil {
			out = FileImage{}
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		next, e := d.Child(part)
		if e != nil {
			return out, e
		}
		owned = append(owned, next)
		d = next
	}
	return d.Read(parts[len(parts)-1], 0640, cap)
}

func walkSnapshot(d *ReadDirectory, prefix string, depth int, files map[string]FileImage) (err error) {
	if depth > 5 {
		return ErrUnavailable
	}
	names, e := d.Names(4096 - len(files))
	if e != nil {
		return e
	}
	for _, name := range names {
		if len(files) >= 4096 {
			return ErrUnavailable
		}
		rel := prefix + name
		// The closed layout determines directories; no symlink-following probe.
		isDir := prefix == "" || (depth == 1 && !(prefix == "inventory/" && name != "owner-index")) || rel == indexDir || rel == indexDir+"/records" || rel == indexDir+"/heads" || rel == indexDir+"/pending"
		if prefix == "" {
			isDir = name == "attempts" || name == "holds" || name == "recovery" || name == "inventory" || name == "capacity" || name == "staging"
			if !isDir {
				return ErrUnavailable
			}
		}
		if depth == 1 {
			isDir = hexString(name, 32) || (prefix == "inventory/" && name == "owner-index")
			if !isDir {
				return ErrUnavailable
			}
		}
		if prefix == indexDir+"/" {
			isDir = name == "records" || name == "heads" || name == "pending"
		}
		if isDir {
			child, e := d.Child(name)
			if e != nil {
				return e
			}
			e = walkSnapshot(child, rel+"/", depth+1, files)
			e = errors.Join(e, child.Close())
			if e != nil {
				return e
			}
		} else {
			image, e := d.Read(name, 0640, 268435456)
			if e != nil {
				return e
			}
			files[rel] = image
		}
	}
	return nil
}

// ReadSnapshot performs a complete finite read without writer.lock, Store.mu or
// F_auth. Every head/record must equal the caller's independently accepted
// commitment. No disk initialization, publication, repair or acknowledgement.
func ReadSnapshot(root *ReadDirectory, baseline SnapshotBaseline) (result ReadSnapshotResult, err error) {
	if baseline.Profile != "pc2-native-owner-index/1" || !digestOK(baseline.FundingDigest) || !digestOK(baseline.Genesis) || baseline.Head.Sequence < 0 || baseline.Head.Sequence >= maxRecords || !digestOK(baseline.Head.Digest) {
		return result, ErrUnavailable
	}
	names, e := root.Names(6)
	sort.Strings(names)
	if e != nil || strings.Join(names, ",") != "attempts,capacity,holds,inventory,recovery,staging" {
		return result, errors.Join(ErrUnavailable, e)
	}
	all := map[string]FileImage{}
	if e := walkSnapshot(root, "", 0, all); e != nil {
		return result, e
	}
	var f nativeFunding
	fi, ok := all[indexDir+"/funding.json"]
	if !ok || fi.Digest != baseline.FundingDigest || decode(fi.Bytes(), &f) != nil || f.Version != "pc2-native-fixture-funding/1" || f.Allocations == nil || f.Native == nil || len(f.Allocations)+len(f.Native) > maxAllocations || f.MetadataIntegrity < 0 {
		return result, ErrUnavailable
	}
	legacy := funding{"pc2-fixture-funding/1", f.Deployment, f.Incarnation, f.Q, f.Metadata, f.Allocations}
	if legacy.validate() != nil || f.MetadataIntegrity > pc2state.AggregateBytes-f.Metadata {
		return result, ErrUnavailable
	}
	result.envelope = f.Metadata + f.MetadataIntegrity
	result.q = f.Q
	alloc := map[string]NativeAllocation{}
	copies := map[string]bool{}
	for _, a := range f.Allocations {
		copies[a.CopyID] = true
		result.envelope += a.MaxBytes + a.Integrity
	}
	for _, a := range f.Native {
		r, ok := NativeRoleCatalog(a.Role)
		ticket, e := TicketID(f.Q, a.SourceOwner, a.SourceKind, a.Role, a.Ordinal)
		if !ok || e != nil || ticket != a.Ticket || a.SourceOwner != "manager" || a.SourceKind != r.Class || !hexString(a.CopyID, 32) || copies[a.CopyID] || alloc[a.Ticket].Ticket != "" || a.MaxBytes < 1 || a.MaxBytes > r.Cap || a.Integrity < 0 || a.Integrity > pc2state.AggregateBytes {
			return result, ErrUnavailable
		}
		copies[a.CopyID] = true
		alloc[a.Ticket] = a
		result.envelope += a.MaxBytes + a.Integrity
	}
	if result.envelope > pc2state.AggregateBytes {
		return result, ErrUnavailable
	}
	var head Head
	hi, ok := all[indexDir+"/head.json"]
	if !ok || decode(hi.Bytes(), &head) != nil || head != baseline.Head || head.Sequence > legacy.metadataTransitions() {
		return result, ErrUnavailable
	}
	chain := make([]FileImage, head.Sequence+1)
	cur := head.Digest
	expected := map[string]string{indexDir + "/funding.json": "funding", indexDir + "/head.json": fmt.Sprint("current/", head.Sequence), indexDir + "/writer.lock": "lock"}
	for seq := head.Sequence; seq >= 0; seq-- {
		image, ok := all[indexDir+"/records/"+cur[7:]+".json"]
		if !ok || image.Digest != cur {
			return result, ErrUnavailable
		}
		chain[seq] = image
		var h struct {
			Sequence int64  `json:"sequence"`
			Previous string `json:"previous"`
		} // Only traversal; closed variants validated below.
		if unmarshalTraversal(image.Bytes(), &h) != nil || h.Sequence != seq {
			return result, ErrUnavailable
		}
		expected[indexDir+"/records/"+cur[7:]+".json"] = fmt.Sprint("record/", seq)
		hb, _ := canonical(Head{seq, cur})
		archive := indexDir + "/heads/" + hash(hb)[7:] + ".json"
		if got, ok := all[archive]; !ok || string(got.Bytes()) != string(hb) {
			return result, ErrUnavailable
		}
		expected[archive] = fmt.Sprint("archive/", seq)
		cur = h.Previous
		if seq > 0 && !digestOK(cur) {
			return result, ErrUnavailable
		}
	}
	g, _ := canonical(genesis())
	if cur != "" || chain[0].Digest != baseline.Genesis || string(chain[0].Bytes()) != string(g) {
		return result, ErrUnavailable
	}
	states := map[string]*copyState{}
	byCopy := map[string]NativeObservation{}
	byLocation := map[string]NativeObservation{}
	for seq := 1; seq < len(chain); seq++ {
		image := chain[seq]
		var tag struct {
			Version string `json:"version"`
		}
		if unmarshalTraversal(image.Bytes(), &tag) != nil {
			return result, ErrUnavailable
		}
		if tag.Version == "pc2-owner-transition/1" {
			var r record
			if decode(image.Bytes(), &r) != nil || apply(states, r, legacy, Head{int64(seq), image.Digest}) != nil {
				return result, ErrUnavailable
			}
			continue
		}
		n, e := DecodeNativeObservation(image.Bytes())
		if e != nil || n.Sequence != int64(seq) || n.FundingDigest != baseline.FundingDigest || n.Deployment != f.Deployment || n.Incarnation != f.Incarnation {
			return result, ErrUnavailable
		}
		a, ok := alloc[n.NativeTicket]
		if !ok || a.CopyID != n.CopyID || n.Bytes > a.MaxBytes || n.Integrity != a.Integrity || (a.Role != n.Role && (n.Destination == nil || *n.Destination != a.Role)) {
			return result, ErrUnavailable
		}
		old, exists := byCopy[n.CopyID]
		if !exists {
			if n.Prior != nil || n.DispositionVersion != 1 {
				return result, ErrUnavailable
			}
		} else {
			oldRaw, _ := canonical(old)
			if n.Prior == nil || *n.Prior != hash(oldRaw) || n.DispositionVersion != old.DispositionVersion+1 || n.NativeTicket != old.NativeTicket || n.Identity != old.Identity {
				return result, ErrUnavailable
			}
			appendOK := n.Role == "generation-journal" && old.Role == n.Role && old.Name == n.Name && old.Directory == n.Directory && n.Bytes > old.Bytes
			renameOK := old.Destination != nil && *old.Destination == n.Role && n.Destination == nil && old.Digest == n.Digest && old.Bytes == n.Bytes
			if !appendOK && !renameOK {
				return result, ErrUnavailable
			}
			delete(byLocation, old.Directory+"/"+old.Name)
		}
		loc := n.Directory + "/" + n.Name
		if prior, occupied := byLocation[loc]; occupied {
			pb, _ := canonical(prior)
			if n.Replaces == nil || *n.Replaces != hash(pb) || n.Identity == prior.Identity || n.CopyID == prior.CopyID {
				return result, ErrUnavailable
			}
		} else if n.Replaces != nil {
			return result, ErrUnavailable
		}
		byCopy[n.CopyID] = n
		byLocation[loc] = n
		result.history = append(result.history, n)
	}
	for _, n := range byLocation {
		result.native = append(result.native, n)
	}
	sort.Slice(result.native, func(i, j int) bool { return result.native[i].StorageID < result.native[j].StorageID })
	for ticket, st := range states {
		if st.installed == nil {
			return result, ErrUnavailable
		}
		a, _ := legacy.find(ticket)
		loc := st.installed.To
		image, ok := all[loc]
		if !ok || image.Digest != st.installed.Digest || image.Length() != st.installed.Bytes || image.Identity != (FileIdentity{st.installed.Identity.Device, st.installed.Identity.Inode, st.installed.Identity.Mount}) {
			return result, ErrUnavailable
		}
		if _, e := pc2state.Decode(st.installed.Codec, image.Bytes()); e != nil {
			return result, ErrUnavailable
		}
		class := string(a.Role)
		if a.Role == Capacity {
			class = "inventory"
		}
		result.entries = append(result.entries, SnapshotEntry{st.installed.StorageID, class, loc, string(st.installed.Codec), image, a.Integrity})
		expected[loc] = "payload"
	}
	aliases := map[[2]uint64]bool{}
	var metadataCost int64
	for loc, image := range all {
		slot, ok := expected[loc]
		if !ok {
			return result, ErrUnavailable
		}
		key := [2]uint64{image.Identity.Device, image.Identity.Inode}
		if aliases[key] {
			return result, ErrUnavailable
		}
		aliases[key] = true
		if slot == "lock" {
			if image.Length() != 0 {
				return result, ErrUnavailable
			}
			continue
		}
		if image.Length() == 0 {
			return result, ErrUnavailable
		}
		if slot == "payload" {
			continue
		}
		id, e := StorageID(CopyIdentity{f.Deployment, f.Incarnation, "manager", "inventory", "inventory", loc, metadataCopyID(baseline.FundingDigest, slot), 1, image.Digest})
		if e != nil {
			return result, e
		}
		// One admitted metadata overhead bound is conservatively assigned to
		// funding.json. It covers this finite profile; never silently use zero.
		integrity := int64(0)
		if slot == "funding" {
			integrity = f.MetadataIntegrity
		}
		metadataCost += image.Length() + integrity
		result.entries = append(result.entries, SnapshotEntry{id, "inventory", loc, "", image, integrity})
	}
	if metadataCost > f.Metadata+f.MetadataIntegrity {
		return result, ErrUnavailable
	}
	result.head = head
	result.held = result.envelope
	for _, e := range result.entries {
		result.held -= e.Image.Length() + e.Integrity
	}
	if result.held < 0 {
		return result, ErrUnavailable
	}
	// Re-read exact endpoint after full scan, without any writer lock.
	final, e := readPath(root, indexDir+"/head.json", maxRecord)
	if e != nil || final != hi {
		return result, errors.Join(ErrUnavailable, e)
	}
	return result, nil
}
