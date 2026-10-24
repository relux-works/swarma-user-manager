package manager

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// MigrationApproval is issued by reviewed root maintenance while all admission is stopped.
// It is read from protected storage, never from the helper protocol or sudo environment.
type MigrationApproval struct {
	Format               string           `json:"format"`
	OriginalDigest       string           `json:"original_digest"`
	JournalTail          genjournal.Floor `json:"journal_tail"`
	ReviewDigest         string           `json:"review_digest"`
	AdmissionStopped     bool             `json:"admission_stopped"`
	ExclusiveMaintenance bool             `json:"exclusive_maintenance"`
}
type legacyState struct {
	Format  string           `json:"format"`
	Floor   genjournal.Floor `json:"floor"`
	Cursor  int64            `json:"cursor"`
	Effects []legacyEffect   `json:"effects"`
}

// A nonempty v1 history has no OS provenance and remains fenced for reviewed reconciliation.
// Raw closed effect decoding is unnecessary because only empty genesis can migrate here.
type legacyEffect map[string]any
type legacyEnvelope struct {
	Format string      `json:"format"`
	State  legacyState `json:"state"`
	Digest string      `json:"sha256"`
}

// MigrateV1 supports only a reconciled empty v1 genesis. Nonempty histories are deliberately
// refused: NSS/ledger observations cannot manufacture missing ownership receipts.
// This root maintenance API is never called by Engine.Handle or the installed helper.
func MigrateV1(ctx context.Context, path string, j Journal, approvalPath string) error {
	return migrateV1(ctx, path, j, approvalPath, 0, "/")
}
func migrateV1(ctx context.Context, path string, j Journal, approvalPath string, owner uint32, anchor string) error {
	if j == nil {
		return fail("effect_evidence_unavailable")
	}
	s, err := openStore(path, owner, anchor)
	if err != nil {
		return err
	}
	defer s.Close()
	unlock, err := s.Lock(ctx, time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	d, err := protectedDir(filepath.Dir(approvalPath), owner, anchor)
	if err != nil {
		return err
	}
	defer d.Close()
	b, err := readFile(d, filepath.Base(approvalPath), owner, MaxRequest)
	if err != nil {
		return err
	}
	var a MigrationApproval
	if strict(b, &a) != nil || a.Format != "station-effects-migration/1" || !hashOK(a.OriginalDigest) || !hashOK(a.ReviewDigest) || !a.AdmissionStopped || !a.ExclusiveMaintenance {
		return fail("effect_evidence_unavailable")
	}
	original, err := readFile(s.dir, "effects.json", owner, maxEvidence)
	if err != nil {
		return err
	}
	var old legacyEnvelope
	if digestBytes(original) != a.OriginalDigest || strict(original, &old) != nil || old.Format != "station-effects-store/1" || old.State.Format != "station-effects/1" || old.Digest != digest(old.State) || old.State.Cursor < 1 || old.State.Effects == nil || len(old.State.Effects) != 0 || old.State.Floor != (genjournal.Floor{Hash: genjournal.ZeroHash}) || a.JournalTail != old.State.Floor {
		return fail("effect_evidence_unavailable")
	}
	return j.Checkpoint(ctx, old.State.Floor, func(v genjournal.View) error {
		if v.Tail != a.JournalTail || len(v.History) != 0 {
			return fail("effect_evidence_unavailable")
		}
		backup := "effects.v1-" + a.OriginalDigest + ".json"
		// Exclusive creation preserves original bytes even if maintenance crashes before replacement.
		f, e := os.OpenFile(filepath.Join(path, backup), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			existing, readErr := readFile(s.dir, backup, owner, maxEvidence)
			if readErr != nil || string(existing) != string(original) {
				return fail("effect_evidence_unavailable")
			}
		} else {
			n, werr := f.Write(original)
			syncErr := f.Sync()
			closeErr := f.Close()
			if werr != nil || syncErr != nil || closeErr != nil || n != len(original) || s.dir.Sync() != nil {
				return fail("state_unavailable")
			}
		}
		next := State{Format: stateFormat, Floor: v.Tail, Cursor: old.State.Cursor, Revision: 1, Effects: []Effect{}, OSRecords: []OSRecord{}}
		data, e := effectBytes(next)
		if e != nil {
			return e
		}
		return atomicFile(s.dir, "effects.json", data, owner)
	})
}
