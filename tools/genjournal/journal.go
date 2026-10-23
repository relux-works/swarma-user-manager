// Package genjournal owns the gen-journal/1 byte and lifecycle validator.
package genjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
)

const (
	Format   = "gen-journal/1"
	MaxLine  = 4096 // Includes LF.
	MaxFile  = 1024 * 1024
	MaxSeq   = int64(9007199254740991)
	ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Refusal contains only a stable code and a one-based line (zero for file errors).
type Refusal struct {
	Code string
	Line int
}

func (r *Refusal) Error() string { return fmt.Sprintf("%s (line %d)", r.Code, r.Line) }
func refuse(code string) error   { return &Refusal{Code: code} }
func at(err error, line int) error {
	if r, ok := err.(*Refusal); ok {
		return &Refusal{r.Code, line}
	}
	return err
}

// Floor is the consumer's durable checkpoint. Hash includes the record's LF.
type Floor struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// Row is the latest authoritative record for a UID; only active admits work.
type Row struct {
	UID        int64  `json:"uid"`
	Generation string `json:"generation"`
	State      string `json:"state"`
	Seq        int64  `json:"seq"`
}

// View includes tombstones and the verified checkpoint; it is never an authority cache.
type View struct {
	Tail Floor `json:"tail"`
	Rows []Row `json:"rows"`
}

// Record has exactly the eight members defined by the format.
type Record struct {
	Seq                             int64
	Prev                            string
	UID                             int64
	Generation, State, Writer, Time string
}

func lowerHex(s string, n int) bool {
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
func validFloor(f Floor) bool {
	return f.Seq >= 0 && f.Seq <= MaxSeq && lowerHex(f.Hash, 64) && (f.Seq != 0 || f.Hash == ZeroHash)
}
func validateRecord(r Record) error {
	if r.Seq < 1 || r.Seq > MaxSeq {
		return refuse("journal_seq")
	}
	if !lowerHex(r.Prev, 64) {
		return refuse("journal_prev")
	}
	if r.UID < 1 || r.UID > 4294967294 {
		return refuse("journal_uid")
	}
	if !lowerHex(r.Generation, 32) || r.Generation == strings.Repeat("0", 32) {
		return refuse("journal_generation")
	}
	switch r.State {
	case "creating", "active", "retiring", "removed":
	default:
		return refuse("journal_state")
	}
	if r.Writer != "user-manager" && r.Writer != "operator-manual" {
		return refuse("journal_writer")
	}
	t, e := time.Parse("2006-01-02T15:04:05Z", r.Time)
	if e != nil || t.Year() < 1 || t.Format("2006-01-02T15:04:05Z") != r.Time {
		return refuse("journal_time")
	}
	return nil
}

// Encode uses the single format-owner CCJ-1 implementation; the returned bytes include LF.
func Encode(r Record) ([]byte, error) {
	if e := validateRecord(r); e != nil {
		return nil, e
	}
	b, e := ccj.Marshal(map[string]any{"format": Format, "seq": r.Seq, "prev": r.Prev, "uid": r.UID, "generation": r.Generation, "state": r.State, "writer": r.Writer, "time": r.Time}, ccj.RegistrationMalformed)
	if e != nil {
		return nil, refuse("journal_json")
	}
	return append(b, '\n'), nil
}
func decode(b []byte) (Record, error) {
	var r Record
	v, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return r, refuse("journal_json")
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 8 {
		return r, refuse("journal_fields")
	}
	for _, k := range []string{"format", "seq", "prev", "uid", "generation", "state", "writer", "time"} {
		if _, ok := m[k]; !ok {
			return r, refuse("journal_fields")
		}
	}
	s, ok := m["format"].(string)
	if !ok || s != Format {
		return r, refuse("journal_format")
	}
	var good bool
	r.Seq, good = m["seq"].(int64)
	if !good {
		return r, refuse("journal_seq")
	}
	r.UID, good = m["uid"].(int64)
	if !good {
		return r, refuse("journal_uid")
	}
	targets := []struct {
		key    string
		target *string
		code   string
	}{{"prev", &r.Prev, "journal_prev"}, {"generation", &r.Generation, "journal_generation"}, {"state", &r.State, "journal_state"}, {"writer", &r.Writer, "journal_writer"}, {"time", &r.Time, "journal_time"}}
	for _, p := range targets {
		s, ok := m[p.key].(string)
		if !ok {
			return r, refuse(p.code)
		}
		*p.target = s
	}
	if e := validateRecord(r); e != nil {
		return r, e
	}
	canonical, e := ccj.Marshal(v, ccj.RegistrationMalformed)
	if e != nil {
		return r, refuse("journal_json")
	}
	if !bytes.Equal(canonical, b) {
		return r, refuse("journal_noncanonical")
	}
	return r, nil
}

func Digest(line []byte) string { h := sha256.Sum256(line); return hex.EncodeToString(h[:]) }

// Verify checks the complete bounded file and requires the supplied durable floor on its chain.
// This byte validator alone does not establish protected paths, locking or restore reconciliation.
func Verify(src io.Reader, floor Floor) (View, error) {
	return verifyUntil(src, floor, time.Time{})
}
func verifyUntil(src io.Reader, floor Floor, deadline time.Time) (View, error) {
	view := View{Tail: Floor{0, ZeroHash}, Rows: []Row{}}
	if !validFloor(floor) {
		return view, refuse("journal_floor")
	}
	b, e := io.ReadAll(io.LimitReader(src, MaxFile+1))
	if e != nil {
		return view, refuse("journal_io")
	}
	if len(b) > MaxFile {
		return view, refuse("journal_file_size")
	}
	rows := map[int64]Row{}
	seen := map[string]bool{}
	floorSeen := floor.Seq == 0
	rest := b
	for i := 1; len(rest) > 0; i++ {
		n := bytes.IndexByte(rest, '\n')
		if n < 0 {
			n = len(rest)
		} else {
			n++
		}
		line := rest[:n]
		rest = rest[n:]
		if !deadline.IsZero() && time.Now().After(deadline) {
			return view, refuse("journal_reader_deadline")
		}
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxLine {
			return view, at(refuse("journal_line_size"), i)
		}
		if line[len(line)-1] != '\n' {
			return view, at(refuse("journal_partial"), i)
		}
		r, e := decode(line[:len(line)-1])
		if e != nil {
			return view, at(e, i)
		}
		if r.Seq != view.Tail.Seq+1 {
			return view, at(refuse("journal_seq"), i)
		}
		if r.Prev != view.Tail.Hash {
			code := "journal_chain"
			if r.Seq == 1 {
				code = "journal_genesis"
			}
			return view, at(refuse(code), i)
		}
		old, exists := rows[r.UID]
		if !exists || r.Generation != old.Generation {
			if seen[r.Generation] {
				return view, at(refuse("journal_generation_reuse"), i)
			}
			if exists && old.State != "removed" {
				return view, at(refuse("journal_overlap"), i)
			}
			if r.State != "creating" {
				return view, at(refuse("journal_transition"), i)
			}
			seen[r.Generation] = true
		} else {
			allowed := old.State == "creating" && (r.State == "active" || r.State == "removed") || old.State == "active" && r.State == "retiring" || old.State == "retiring" && r.State == "removed"
			if !allowed {
				return view, at(refuse("journal_transition"), i)
			}
		}
		rows[r.UID] = Row{r.UID, r.Generation, r.State, r.Seq}
		view.Tail = Floor{r.Seq, Digest(line)}
		if r.Seq == floor.Seq {
			if view.Tail.Hash != floor.Hash {
				return view, at(refuse("journal_fork"), i)
			}
			floorSeen = true
		}
	}
	if !floorSeen {
		return view, refuse("journal_rollback")
	}
	for _, row := range rows {
		view.Rows = append(view.Rows, row)
	}
	sort.Slice(view.Rows, func(i, j int) bool { return view.Rows[i].UID < view.Rows[j].UID })
	return view, nil
}

// Active distinguishes absent identity, reused UID and inactive lifecycle evidence.
func (v View) Active(uid int64, generation string) error {
	for _, r := range v.Rows {
		if r.UID == uid {
			if r.Generation != generation {
				return refuse("generation_mismatch")
			}
			if r.State != "active" {
				return refuse("generation_inactive")
			}
			return nil
		}
	}
	return refuse("generation_missing")
}
