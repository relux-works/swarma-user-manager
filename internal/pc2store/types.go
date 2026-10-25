// Package pc2store supplies protected PC2 persistence mechanics. Production
// opening is unavailable until installation, funding and custody are specified.
package pc2store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-user-manager/internal/pc2state"
)

var (
	ErrUnavailable   = errors.New("PC2 store unavailable")
	ErrConflict      = errors.New("PC2 predecessor changed")
	ErrIndeterminate = errors.New("PC2 publication indeterminate; retain funding")
)

const (
	maxRecord      = 65536
	maxRecords     = 1024
	maxAllocations = 256
)

type Role string

const (
	Attempts  Role = "attempts"
	Holds     Role = "holds"
	Recovery  Role = "recovery"
	Inventory Role = "inventory"
	Capacity  Role = "capacity"
)

var roles = []Role{Attempts, Holds, Recovery, Inventory, Capacity}

func validRole(r Role) bool {
	for _, v := range roles {
		if r == v {
			return true
		}
	}
	return false
}
func accepts(r Role, k pc2state.Kind) bool {
	switch r {
	case Attempts:
		return k == pc2state.ActivationAttempt
	case Holds:
		return k == pc2state.Hold
	case Recovery:
		return k == pc2state.RecoveryRecord
	case Inventory:
		return k == pc2state.ManagerInventory || k == pc2state.RecoveryHistory || k == pc2state.RecoveryGuard || k == pc2state.CapacityInventory
	case Capacity:
		return k == pc2state.CapacityInventory
	}
	return false
}

type Head struct {
	Sequence int64  `json:"sequence"`
	Digest   string `json:"digest"`
}
type Receipt struct {
	Head                Head
	StorageID, Location string
}

// Report is physical accounting plus retained reservations, never new credit.
// An error accompanying a Report forbids census/admission even if bytes are known.
type Report struct {
	Head                                                                                                               Head
	Objects, MaterializedBytes, IntegrityBytes, MetadataBytes, MetadataObjects, ReservedBytes, OrphanBytes, TotalBytes int64
}

// CopyIdentity retains every unhashed storage-ID input; it confers no authority.
type CopyIdentity struct {
	Deployment, Incarnation, Owner, Role, DirectoryRole, RelativeName, CopyID string
	DispositionVersion                                                        int64
	ContentDigest                                                             string
}

func StorageID(i CopyIdentity) (string, error) {
	if !text(i.Deployment) || !text(i.Incarnation) || (i.Owner != "manager" && i.Owner != "keymaker") || !admittedIdentityRole(i.Owner, i.Role) || !admittedDirectory(i.Owner, i.DirectoryRole) || !relative(i.RelativeName) || !hexString(i.CopyID, 32) || i.DispositionVersion < 1 || i.DispositionVersion > pc2state.SafeInteger || !digestOK(i.ContentDigest) {
		return "", ErrUnavailable
	}
	// Role catalogs are checked by the installed mapping before this pure recipe.
	b, e := canonical([]any{"pc2-copy-id/1", i.Deployment, i.Incarnation, i.Owner, i.Role, i.DirectoryRole, i.RelativeName, i.CopyID, i.DispositionVersion, i.ContentDigest})
	if e != nil {
		return "", e
	}
	return "pc2o1:" + hash(b)[7:], nil
}
func TicketID(q, owner, kind, role string, ordinal int64) (string, error) {
	if !digestOK(q) || (owner != "manager" && owner != "keymaker") || !text(kind) || !text(role) || ordinal < 1 || ordinal > pc2state.SafeInteger {
		return "", ErrUnavailable
	}
	b, e := canonical([]any{"pc2-ticket-id/1", q, owner, kind, role, ordinal})
	if e != nil {
		return "", e
	}
	return "pc2t1:" + hash(b)[7:], nil
}
func admittedIdentityRole(owner, role string) bool {
	if owner == "manager" {
		return role == "attempts" || role == "holds" || role == "recovery" || role == "inventory" || role == "staging"
	}
	for _, v := range []string{"installed", "artifacts", "recovery", "staging", "pending_proofs", "policy_history", "root_history", "migration_history", "reservation_metadata"} {
		if role == v {
			return true
		}
	}
	return false
}
func admittedDirectory(owner, role string) bool {
	return admittedIdentityRole(owner, role) || (owner == "manager" && role == "capacity")
}
func text(s string) bool {
	if len(s) < 1 || len(s) > 255 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func relative(s string) bool {
	if !text(s) || strings.HasPrefix(s, "/") || strings.Contains(s, "\\") {
		return false
	}
	for _, v := range strings.Split(s, "/") {
		if v == "" || v == "." || v == ".." {
			return false
		}
	}
	return path.Clean(s) == s
}
func hexString(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func digestOK(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hexString(strings.TrimPrefix(s, "sha256:"), 64)
}
func hash(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, ErrUnavailable
	}
	o, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, ErrUnavailable
	}
	b, e = ccj.Marshal(o, ccj.RegistrationMalformed)
	if e != nil {
		return nil, ErrUnavailable
	}
	return b, nil
}
func decode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > maxRecord || !boundedDepth(raw) {
		return ErrUnavailable
	}
	o, e := ccj.Parse(raw, ccj.RegistrationMalformed)
	if e != nil {
		return ErrUnavailable
	}
	b, e := ccj.Marshal(o, ccj.RegistrationMalformed)
	if e != nil || !bytes.Equal(raw, b) {
		return ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrUnavailable
	}
	b, e = canonical(v)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrUnavailable
	}
	return nil
}

// The funding wire format is deliberately fixture-specific. There is no
// production constructor for it and no conversion from calculator/preflight.
type allocation struct {
	Ticket    string `json:"ticket"`
	CopyID    string `json:"copy_id"`
	Role      Role   `json:"role"`
	Version   int64  `json:"disposition_version"`
	MaxBytes  int64  `json:"max_bytes"`
	Integrity int64  `json:"integrity_bytes"`
	Ordinal   int64  `json:"ordinal"`
}
type funding struct {
	Version     string       `json:"version"`
	Deployment  string       `json:"deployment"`
	Incarnation string       `json:"incarnation"`
	Q           string       `json:"q"`
	Metadata    int64        `json:"metadata_bytes"`
	Allocations []allocation `json:"allocations"`
}

func (f funding) validate() error {
	if f.Version != "pc2-fixture-funding/1" || !hexString(f.Deployment, 32) || !hexString(f.Incarnation, 32) || !digestOK(f.Q) || f.Metadata < maxRecord*8 || f.Metadata > pc2state.AggregateBytes || len(f.Allocations) > maxAllocations || f.Allocations == nil {
		return ErrUnavailable
	}
	seen := map[string]bool{}
	copies := map[string]bool{}
	total := f.Metadata
	for _, a := range f.Allocations {
		want, e := TicketID(f.Q, "keymaker", "reservation_metadata", string(a.Role), a.Ordinal)
		if e != nil || a.Ticket != want || !validRole(a.Role) || !hexString(a.CopyID, 32) || a.Version < 1 || a.Version > pc2state.SafeInteger || a.MaxBytes < 1 || a.MaxBytes > pc2state.AggregateBytes || a.Integrity < 0 || a.Integrity > pc2state.AggregateBytes || seen[a.Ticket] || copies[a.CopyID] {
			return ErrUnavailable
		}
		seen[a.Ticket] = true
		copies[a.CopyID] = true
		total += a.MaxBytes + a.Integrity
		if total > pc2state.AggregateBytes {
			return ErrUnavailable
		}
	}
	return nil
}

// Four bootstrap slots cover funding/genesis/archive/current head. Each later
// transition owns three disjoint maxRecord slots: record, archived head and
// current-head output. Renaming a slot's file never makes that slot reusable.
func (f funding) metadataTransitions() int64 { return (f.Metadata - 4*maxRecord) / (3 * maxRecord) }

func (f funding) find(ticket string) (allocation, bool) {
	for _, a := range f.Allocations {
		if a.Ticket == ticket {
			return a, true
		}
	}
	return allocation{}, false
}

// location keeps the digest basename and separates same-role equal-byte copies.
func location(a allocation, digest string, staging bool) string {
	r := string(a.Role)
	if staging {
		r = "staging"
	}
	return r + "/" + a.CopyID + "/" + digest[7:] + ".json"
}
func (f funding) identity(a allocation, digest, loc string) (string, error) {
	dir := string(a.Role)
	if strings.HasPrefix(loc, "staging/") {
		dir = "staging"
	}
	role := string(a.Role)
	if a.Role == Capacity {
		role = "inventory"
	}
	return StorageID(CopyIdentity{f.Deployment, f.Incarnation, "manager", role, dir, loc, a.CopyID, a.Version, digest})
}

type inode struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mount  uint64 `json:"mount"`
}
type record struct {
	Version   string        `json:"version"`
	Sequence  int64         `json:"sequence"`
	Previous  string        `json:"previous"`
	Event     string        `json:"event"`
	Ticket    string        `json:"ticket"`
	Digest    string        `json:"content_digest"`
	Bytes     int64         `json:"bytes"`
	Codec     pc2state.Kind `json:"codec"`
	From      string        `json:"from"`
	To        string        `json:"to"`
	StorageID string        `json:"storage_id"`
	Identity  inode         `json:"identity"`
}

func genesis() record { return record{Version: "pc2-owner-transition/1", Event: "genesis"} }

type baseline struct {
	FundingDigest string
	Genesis       string
	Floor         Head
}

func boundedDepth(raw []byte) bool {
	depth := 0
	quoted, escape := false, false
	for _, c := range raw {
		if quoted {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > 16 {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !quoted
}
