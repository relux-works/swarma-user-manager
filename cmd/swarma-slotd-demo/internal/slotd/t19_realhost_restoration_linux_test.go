//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type t19Window struct {
	ProductionBackup, ProductionSHA256, TemporaryPolicy, Ready string
	WalletKind                                                 string
	PeerUID                                                    uint32
}

func t19WindowPolicies(production, qualification policy) error {
	// Preserve the identity and schema used to decode this owned stopped record
	// across a daemon restart. A typed-v2/live rental cannot be repurposed here.
	if production.Version != 0 || qualification.Version != 0 {
		return errors.New("observational maintenance requires the installed literal v0 policy; typed-v2 migration is out of scope")
	}
	if production.CallerUser != qualification.CallerUser || production.UIDBase != qualification.UIDBase || production.HomeRoot != qualification.HomeRoot || production.Socket != qualification.Socket || production.Caps != qualification.Caps || !slices.Equal(production.Egress, qualification.Egress) {
		return errors.New("qualification may change only the payload, not production identity/caps/egress")
	}
	if production.Adopted == nil || qualification.Adopted == nil || *production.Adopted != *qualification.Adopted {
		return errors.New("qualification must preserve the production adopted declaration")
	}
	if production.payloadDigest() == qualification.payloadDigest() {
		return errors.New("production already authorizes the probe payload")
	}
	return nil
}
func t19ReadProductionWindow(w t19Window, p policy, policyPath, host string) (policy, error) {
	var prod policy
	if w.ProductionBackup == policyPath || w.TemporaryPolicy == policyPath || w.TemporaryPolicy == w.ProductionBackup || w.Ready == "" {
		return prod, errors.New("separate production backup, temporary policy and ready paths are required")
	}
	if w.WalletKind != "REAL" && w.WalletKind != "STAND_IN" {
		return prod, errors.New("--wallet-kind must be REAL or STAND_IN")
	}
	if host == "rt-stations" && w.WalletKind != "STAND_IN" {
		return prod, errors.New("rt-stations has a stand-in, not a real wallet")
	}
	if host == "stations1" && w.WalletKind != "REAL" {
		return prod, errors.New("stations1 requires the real connection-only wallet observation")
	}
	temporary, e := readProtected(w.TemporaryPolicy, 0, maxPolicyBytes)
	if e != nil {
		return prod, e
	}
	current, e := readProtected(policyPath, 0640, maxPolicyBytes)
	if e != nil || digest(temporary) != digest(current) {
		return prod, errors.New("temporary policy must initially equal the installed qualification policy bytes")
	}
	b, err := readProtected(w.ProductionBackup, 0640, maxPolicyBytes)
	if err != nil {
		return prod, err
	}
	if !digestPattern.MatchString(w.ProductionSHA256) || digest(b) != w.ProductionSHA256 {
		return prod, errors.New("production backup differs from pre-window pin")
	}
	prod, err = parsePolicy(b)
	if err != nil {
		return prod, err
	}
	if err = t19WindowPolicies(prod, p); err != nil {
		return prod, err
	}
	return prod, verifyPayload(prod)
}

// Refusal is meaningful only on this same owned STOPPED binding with time
// remaining, not an absent/destroyed record or an expired rental. Production's
// payload digest must differ. A pre/post status proves no transition occurred.
func t19ProductionRefusal(ctx context.Context, r *t19Rental, productionDigest string) (response, error) {
	if productionDigest == r.Binding.PayloadSHA256 {
		return response{}, errors.New("production still authorizes the probe")
	}
	before, err := r.query(ctx, "status")
	if err != nil {
		return before, err
	}
	expiry, e := time.Parse(time.RFC3339, r.Binding.NotAfter)
	if e != nil || time.Until(expiry) < 60*time.Second || before.State != stopped || !r.owns(before) {
		return before, errors.New("refusal control lacks a fresh owned stopped probe binding")
	}
	refused, err := r.query(ctx, "start")
	if err == nil || refused.Error != invalidState || !r.owns(refused) {
		return refused, errors.New("production did not refuse the probe with bound invalid_state")
	}
	after, err := r.query(ctx, "status")
	if err != nil || after.State != stopped || !r.owns(after) {
		return after, errors.New("refused probe changed the slot binding/state")
	}
	return refused, nil
}
func t19RestoreWindow(ctx context.Context, w t19Window, prod policy, policyPath, pin string, r *t19Rental, report *t19RealHostReport) error {
	oldPID, err := t19MainPID(ctx, "swarma-slotd-demo.service")
	if err != nil {
		return err
	}
	stopResponse, err := r.query(ctx, "stop")
	if err != nil {
		return err
	}
	if stopResponse.State != stopped || !r.owns(stopResponse) {
		return errors.New("own probe did not stop before policy restoration")
	}
	b, err := json.MarshalIndent(struct {
		Phase            string             `json:"phase"`
		Slot             string             `json:"slot"`
		ProductionSHA256 string             `json:"production_sha256"`
		Stopped          response           `json:"stopped_binding"`
		DaemonPID        int                `json:"daemon_pid"`
		Observed         *t19RealHostReport `json:"observations"`
	}{"STOPPED_RESTORE_PRODUCTION_AND_REMOVE_TEMPORARY_POLICY", r.Slot, w.ProductionSHA256, stopResponse, oldPID, report}, "", "  ")
	if err != nil {
		return err
	}
	if err = t19WriteReady(w.Ready, append(b, '\n')); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "T19: own probe stopped; restore production policy, remove temporary qualification policy and restart the installed daemon now; see --ready evidence")
	for {
		current, readErr := readProtected(policyPath, 0640, maxPolicyBytes)
		_, absentErr := os.Lstat(w.TemporaryPolicy)
		pid, pidErr := t19MainPID(ctx, "swarma-slotd-demo.service")
		if readErr == nil && digest(current) == w.ProductionSHA256 && errors.Is(absentErr, os.ErrNotExist) && pidErr == nil && pid != oldPID {
			if _, err = t19VerifyDaemon(ctx, policyPath, pin); err != nil {
				return err
			}
			if err = verifyPayload(prod); err != nil {
				return err
			}
			refused, err := t19ProductionRefusal(ctx, r, prod.payloadDigest())
			if err != nil {
				return err
			}
			// The backup is also re-read, not inferred unchanged from its old digest.
			backup, err := readProtected(w.ProductionBackup, 0640, maxPolicyBytes)
			if err != nil || digest(backup) != w.ProductionSHA256 {
				return errors.New("production backup changed during window")
			}
			report.Restoration = t19Item{ID: "restoration", Verdict: t19Pass, Evidence: []t19Evidence{{Claim: "temporary policy removed; original production bytes restored and read back; restarted installed daemon refused the same stopped probe binding with invalid_state; no state change", Observed: struct {
				ProductionSHA256      string
				TemporaryPolicyAbsent bool
				PriorPID, RestoredPID int
				Refusal               response
			}{digest(current), true, oldPID, pid, refused}}}}
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("production policy restoration evidence incomplete: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func t19WriteReady(path string, b []byte) error {
	partial := path + ".partial"
	f, err := t19OpenOutput(partial)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Link publishes atomically without replacing a pre-existing artifact.
	if err = os.Link(partial, path); err != nil {
		return err
	}
	if err = os.Remove(partial); err != nil {
		return err
	}
	parent, err := openTrustedDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
