//go:build linux

package pc2store

import (
	"encoding/json"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

type JournalCheckpoint struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}
type NativeIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mount  uint64 `json:"mount"`
}
type NativeObservation struct {
	Version            string             `json:"version"`
	Sequence           int64              `json:"sequence"`
	Previous           string             `json:"previous"`
	FundingDigest      string             `json:"funding_digest"`
	NativeTicket       string             `json:"native_ticket"`
	Deployment         string             `json:"deployment_id"`
	Incarnation        string             `json:"authority_incarnation"`
	Role               string             `json:"native_role"`
	Directory          string             `json:"directory_role"`
	Name               string             `json:"relative_name"`
	Destination        *string            `json:"destination_role"`
	CopyID             string             `json:"copy_id"`
	DispositionVersion int64              `json:"disposition_version"`
	Prior              *string            `json:"previous_observation"`
	Replaces           *string            `json:"replaces"`
	Digest             string             `json:"content_digest"`
	Bytes              int64              `json:"bytes"`
	Integrity          int64              `json:"integrity_bytes"`
	StorageID          string             `json:"storage_id"`
	Identity           NativeIdentity     `json:"identity"`
	Encoding           string             `json:"encoding"`
	Revision           *int64             `json:"revision"`
	Floor              *JournalCheckpoint `json:"journal_floor"`
	Tail               *JournalCheckpoint `json:"journal_tail"`
}

type NativeRoleSpec struct {
	Directory, Class, Encoding string
	Cap                        int64
}

// NativeRoleCatalog is finite; its return values contain no caller maps.
func NativeRoleCatalog(role string) (NativeRoleSpec, bool) {
	switch role {
	case "generation-journal":
		return NativeRoleSpec{"native-generations", "recovery", "journal", 1048576}, true
	case "generation-pending":
		return NativeRoleSpec{"native-generations", "recovery", "pending", 512}, true
	case "effects-store":
		return NativeRoleSpec{"native-effects", "recovery", "effects", 8388608}, true
	case "effects-ledger":
		return NativeRoleSpec{"native-effects", "recovery", "ledger", 8388608}, true
	case "recovery-evidence":
		return NativeRoleSpec{"native-effects", "recovery", "evidence", 65536}, true
	case "attempt-evidence":
		return NativeRoleSpec{"native-effects", "attempts", "evidence", 65536}, true
	case "hold-evidence":
		return NativeRoleSpec{"native-effects", "holds", "evidence", 65536}, true
	case "effects-temporary":
		return NativeRoleSpec{"native-effects", "staging", "", 8388608}, true
	case "pending-temporary":
		return NativeRoleSpec{"native-generations", "staging", "pending", 512}, true
	}
	return NativeRoleSpec{}, false
}

func nativeName(n NativeObservation) bool {
	switch n.Role {
	case "generation-journal":
		return n.Name == "journal"
	case "generation-pending":
		return n.Name == "writer.pending"
	case "effects-store":
		return n.Name == "effects.json"
	case "effects-ledger":
		return n.Name == "ledger.json"
	case "recovery-evidence", "attempt-evidence", "hold-evidence":
		return n.Name == "evidence-"+n.Digest[7:]+".json"
	case "effects-temporary":
		return strings.HasPrefix(n.Name, ".write-") && hexString(strings.TrimPrefix(n.Name, ".write-"), 32)
	case "pending-temporary":
		return strings.HasPrefix(n.Name, ".pending-") && hexString(strings.TrimPrefix(n.Name, ".pending-"), 32)
	}
	return false
}
func checkpointOK(c *JournalCheckpoint) bool {
	return c != nil && c.Seq >= 0 && c.Seq <= pc2state.SafeInteger && hexString(c.Hash, 64) && (c.Seq != 0 || c.Hash == strings.Repeat("0", 64))
}

// DecodeNativeObservation validates representation only, never funding/custody.
func DecodeNativeObservation(raw []byte) (NativeObservation, error) {
	var n NativeObservation
	if len(raw) > 8192 || decode(raw, &n) != nil {
		return n, ErrUnavailable
	}
	r, ok := NativeRoleCatalog(n.Role)
	if !ok || n.Version != "pc2-native-observation/1" || n.Sequence < 1 || n.Sequence >= maxRecords || !digestOK(n.Previous) || !digestOK(n.FundingDigest) || !strings.HasPrefix(n.NativeTicket, "pc2t1:") || !hexString(strings.TrimPrefix(n.NativeTicket, "pc2t1:"), 64) || !hexString(n.Deployment, 32) || !hexString(n.Incarnation, 32) || !hexString(n.CopyID, 32) || n.DispositionVersion < 1 || n.DispositionVersion > pc2state.SafeInteger || !digestOK(n.Digest) || n.Directory != r.Directory || n.Bytes < 0 || n.Bytes > r.Cap || n.Integrity < 0 || n.Integrity > pc2state.AggregateBytes || !nativeName(n) {
		return n, ErrUnavailable
	}
	for _, v := range []uint64{n.Identity.Device, n.Identity.Inode, n.Identity.Mount} {
		if v == 0 || v > uint64(pc2state.SafeInteger) {
			return n, ErrUnavailable
		}
	}
	for _, d := range []*string{n.Prior, n.Replaces} {
		if d != nil && !digestOK(*d) {
			return n, ErrUnavailable
		}
	}
	encoding := r.Encoding
	if n.Role == "effects-temporary" || n.Role == "pending-temporary" {
		if n.Destination == nil {
			return n, ErrUnavailable
		}
		dest, ok := NativeRoleCatalog(*n.Destination)
		if !ok || dest.Class == "staging" || (n.Role == "pending-temporary" && *n.Destination != "generation-pending") || (n.Role == "effects-temporary" && dest.Directory != "native-effects") || n.Bytes > dest.Cap {
			return n, ErrUnavailable
		}
		encoding = dest.Encoding
	} else if n.Destination != nil {
		return n, ErrUnavailable
	}
	if n.Encoding != encoding {
		return n, ErrUnavailable
	}
	switch encoding {
	case "journal":
		if n.Revision != nil || !checkpointOK(n.Floor) || !checkpointOK(n.Tail) || n.Floor.Seq > n.Tail.Seq {
			return n, ErrUnavailable
		}
	case "effects":
		if n.Revision == nil || *n.Revision < 1 || *n.Revision > pc2state.SafeInteger || !checkpointOK(n.Floor) || n.Tail != nil {
			return n, ErrUnavailable
		}
	case "ledger":
		if n.Revision != nil || n.Floor != nil || !checkpointOK(n.Tail) {
			return n, ErrUnavailable
		}
	default:
		if n.Revision != nil || n.Floor != nil || n.Tail != nil {
			return n, ErrUnavailable
		}
	}
	if n.Replaces != nil && n.Role != "effects-store" && n.Role != "effects-ledger" {
		return n, ErrUnavailable
	}
	want, e := StorageID(CopyIdentity{n.Deployment, n.Incarnation, "manager", r.Class, n.Directory, n.Name, n.CopyID, n.DispositionVersion, n.Digest})
	if e != nil || n.StorageID != want {
		return n, ErrUnavailable
	}
	return n, nil
}

// cloneNative prevents pointer members from aliasing a retained snapshot.
func cloneNative(n NativeObservation) NativeObservation {
	b, _ := json.Marshal(n)
	var out NativeObservation
	_ = json.Unmarshal(b, &out)
	return out
}
