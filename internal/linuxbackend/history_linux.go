//go:build linux

package linuxbackend

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

type ownership struct {
	intent  manager.OSIntent
	receipt manager.Receipt
	seq     int64
}

func decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return refuse("effect_evidence_unavailable")
	}
	return nil
}

// The core authenticates record schemas and lifecycle references. This boundary
// additionally verifies the retained chain and exact resolving flight before it
// uses any original creation object as a primitive ownership receipt.
func history(records []manager.OSRecord) ([]ownership, error) {
	intents := map[string]manager.OSIntent{}
	flights := map[string]manager.Flight{}
	flightHashes := map[string]string{}
	out := []ownership{}
	prev := strings.Repeat("0", 64)
	for n, r := range records {
		if r.Seq != int64(n+1) || r.Prev != prev {
			return nil, refuse("effect_evidence_unavailable")
		}
		prev = sum(r)
		switch r.Kind {
		case "intent":
			var i manager.OSIntent
			if decode(r.Body, &i) != nil || i.Key != manager.IntentKey(i) || intents[i.Key].Key != "" {
				return nil, refuse("effect_evidence_unavailable")
			}
			intents[i.Key] = i
		case "flight":
			var f manager.Flight
			if decode(r.Body, &f) != nil || intents[f.Key].Key == "" || flights[f.Key].Key != "" {
				return nil, refuse("effect_evidence_unavailable")
			}
			flights[f.Key] = f
			flightHashes[f.Key] = sum(r)
		case "receipt":
			var v manager.Receipt
			if decode(r.Body, &v) != nil {
				return nil, refuse("effect_evidence_unavailable")
			}
			f := flights[v.Key]
			i := intents[v.Key]
			if f.Key == "" || v.Attempt != f.Attempt || v.FlightHash != flightHashes[v.Key] || v.ManifestDigest != i.ManifestDigest {
				return nil, refuse("effect_evidence_unavailable")
			}
			if v.Outcome == "unknown" {
				continue
			}
			if v.Outcome != "applied" && v.Outcome != "absent" && v.Outcome != "no_progress" {
				return nil, refuse("effect_evidence_unavailable")
			}
			delete(flights, v.Key)
			if v.Outcome == "applied" {
				out = append(out, ownership{i, v, r.Seq})
			}
		case "incident", "resolution": // Core rejects unresolved incidents before calling the adapter.
		default:
			return nil, refuse("effect_evidence_unavailable")
		}
	}
	return out, nil
}
func identityReceipts(records []manager.OSRecord, o manager.Effect, id linuxos.ReservedIdentity) ([]linuxos.IdentityReceipt, error) {
	all, e := history(records)
	if e != nil {
		return nil, e
	}
	out := []linuxos.IdentityReceipt{}
	seen := map[string]bool{}
	for _, v := range all {
		i := v.intent
		if i.Operation != "group_create" && i.Operation != "account_create" {
			continue
		}
		if i.Identity.UID != o.Account.UID || i.Identity.GID != o.Account.GID || i.Identity.Username != o.Account.Username || i.Identity.Home != o.Account.Home || i.Identity.Generation != o.Account.Generation || i.Identity.Previous != "" || i.Effect.Owner != o.Owner || i.Effect.RequestID != o.Request.ID {
			continue
		}
		if seen[i.Operation] || len(v.receipt.Objects) != 1 {
			return nil, refuse("effect_evidence_unavailable")
		}
		seen[i.Operation] = true
		s := linuxos.AccountSet{}
		switch i.Operation {
		case "account_create":
			var a manager.AccountObject
			if decode(v.receipt.Objects[0], &a) != nil || a.Kind != "account" || a.Name != id.Name || a.UID != int64(id.UID) || a.GID != int64(id.GID) || a.Home != id.Home || a.Shell != "/usr/sbin/nologin" || !a.PasswordLocked || a.Supplementary == nil || len(a.Supplementary) != 0 {
				return nil, refuse("effect_evidence_unavailable")
			}
			s.Accounts = []linuxos.AccountIdentity{{Name: a.Name, UID: id.UID, GID: id.GID, Home: a.Home, Shell: a.Shell, PasswordLocked: true, SupplementaryGIDs: []uint32{}}}
		case "group_create":
			var g manager.GroupObject
			if decode(v.receipt.Objects[0], &g) != nil || g.Kind != "group" || g.Name != id.Name || g.GID != int64(id.GID) || g.Members == nil || len(g.Members) != 0 {
				return nil, refuse("effect_evidence_unavailable")
			}
			s.Groups = []linuxos.GroupIdentity{{Name: g.Name, GID: id.GID, Members: []string{}}}
		}
		out = append(out, linuxos.IdentityReceipt{Key: i.Key, Operation: i.Operation, Identity: id, Accounts: s})
	}
	return out, nil
}
func sameIntent(a, b manager.OSIntent) bool { return reflect.DeepEqual(a, b) }
func fileObject(s linuxos.FSIdentity) manager.FileObject {
	return manager.FileObject{Kind: "fs", Device: s.Device, Inode: s.Inode, Type: s.Type, UID: int64(s.UID), GID: int64(s.GID), Mode: s.Mode, Nlink: s.Nlink, Digest: s.Digest}
}
func fsObject(s manager.FileObject) (linuxos.FSIdentity, error) {
	if s.Kind != "fs" || s.UID < 0 || s.UID > 4294967295 || s.GID < 0 || s.GID > 4294967295 || s.Inode == 0 || s.Nlink == 0 || s.Mode > 07777 || (s.Type != "directory" && s.Type != "regular" && s.Type != "symlink") || (s.Type == "regular" && !hash(s.Digest)) || (s.Type != "regular" && s.Digest != "") {
		return linuxos.FSIdentity{}, refuse("effect_evidence_unavailable")
	}
	return linuxos.FSIdentity{Device: s.Device, Inode: s.Inode, Type: s.Type, UID: uint32(s.UID), GID: uint32(s.GID), Mode: s.Mode, Nlink: s.Nlink, Digest: s.Digest}, nil
}
