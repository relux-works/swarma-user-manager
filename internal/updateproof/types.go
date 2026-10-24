// Package updateproof implements A3 evidence, never pin publication or admission.
package updateproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
)

type Refusal string

func (r Refusal) Error() string { return string(r) }

const (
	ErrStore     Refusal = "update_store_unavailable"
	ErrConflict  Refusal = "update_event_conflict"
	ErrGap       Refusal = "update_hook_gap"
	ErrScope     Refusal = "update_scope_refused"
	ErrOwnership Refusal = "update_unpackaged_leaf"
	ErrChecksum  Refusal = "update_installed_checksum"
	ErrChain     Refusal = "update_archive_chain"
	ErrTrust     Refusal = "update_signature_refused"
	ErrTime      Refusal = "update_time_refused"
	ErrRollback  Refusal = "update_downgrade_refused"
	ErrTool      Refusal = "update_trust_base_drift"
	ErrMissing   Refusal = "update_missing_evidence"
)

func Digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digestOK(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == hex.EncodeToString(b)
}
func same(a, b any) bool { return reflect.DeepEqual(a, b) }
func closed(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return ErrStore
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrStore
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Limits struct {
	Bytes            int64
	Entries, Members int
}

func (l Limits) valid() bool {
	return l.Bytes > 0 && l.Bytes <= 128<<20 && l.Entries > 0 && l.Entries <= 100000 && l.Members > 0 && l.Members <= 100000
}

type ID struct {
	Boot     string `json:"boot"`
	Sequence uint64 `json:"sequence"`
	Kind     string `json:"kind"`
}

func (id ID) valid() bool {
	return tokenRE.MatchString(id.Boot) && id.Sequence > 0 && (id.Kind == "aggregate" || id.Kind == "invocation")
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Architecture  string `json:"architecture"`
	Status        string `json:"status"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

func (p Package) key() string { return p.Name + ":" + p.Architecture }

type Leaf struct {
	MD5          string `json:"md5"`
	DpkgSHA256   string `json:"dpkg_sha256"`
	Path         string `json:"path"`
	Package      string `json:"package"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Mode         uint32 `json:"mode"`
	UID          uint32 `json:"uid"`
	GID          uint32 `json:"gid"`
}
type Snapshot struct {
	DatabaseSHA256  string    `json:"database_sha256,omitempty"`
	Packages        []Package `json:"packages"`
	Leaves          []Leaf    `json:"leaves"`
	PendingTriggers bool      `json:"pending_triggers"`
}

func (s Snapshot) valid(l Limits) bool {
	if s.DatabaseSHA256 != "" && !digestOK(s.DatabaseSHA256) {
		return false
	}
	if len(s.Packages) == 0 || len(s.Packages) > l.Members || len(s.Leaves) > l.Members {
		return false
	}
	last := ""
	for _, p := range s.Packages {
		if !nameRE.MatchString(p.Name) || !nameRE.MatchString(p.Architecture) || !validVersion(p.Version) || p.key() <= last || (p.ArchiveSHA256 != "" && !digestOK(p.ArchiveSHA256)) {
			return false
		}
		last = p.key()
	}
	last = ""
	for _, f := range s.Leaves {
		if !leafPath(f.Path) || f.Path <= last || !digestOK(f.SHA256) {
			return false
		}
		last = f.Path
	}
	return true
}

type Invocation struct {
	ID     ID       `json:"id"`
	Parent ID       `json:"parent"`
	Before Snapshot `json:"before"`
	After  Snapshot `json:"after"`
	Status string   `json:"status"`
}
type Batch struct {
	ID          ID           `json:"id"`
	Invocations []Invocation `json:"invocations"`
}
type ScanResult struct {
	Pending []Batch `json:"pending"`
}
