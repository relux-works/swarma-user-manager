package manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The candidate reader uses the same protected closed policy checks but permits
// P0; normal admission still rejects it. Missing newly mandatory policy fields
// cannot silently default, and a properly pinned policy remains a valid neighbor.
func TestQualificationCandidatePolicy(t *testing.T) {
	h := setup(t)
	p := h.e.Policy
	p.NoLauncher = true
	p.Qualified = false
	p.QualificationDigest = strings.Repeat("0", 64)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "policy.json")
	raw, _ := canonical(p)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e := p.validate(); e != nil {
		t.Fatal("fixture policy invalid", e)
	}
	var decoded Policy
	if e := strict(raw, &decoded); e != nil {
		t.Fatal("fixture bytes invalid", e)
	}
	candidate, e := loadCandidatePolicyAt(path, uint32(os.Getuid()), dir)
	if e != nil || candidate.Qualified {
		t.Fatal("P0 candidate", e)
	}
	if _, e = loadPolicyAt(path, uint32(os.Getuid()), dir); errorCode(e) != "qualification_required" {
		t.Fatal("P0 admitted")
	}
	p.Qualified = true
	p.QualificationDigest = strings.Repeat("a", 64)
	raw, _ = canonical(p)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadPolicyAt(path, uint32(os.Getuid()), dir); e != nil {
		t.Fatal("qualified policy neighbor", e)
	}
	raw = []byte(strings.Replace(string(raw), `"no_launcher":true,`, "", 1))
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadCandidatePolicyAt(path, uint32(os.Getuid()), dir); errorCode(e) != "qualification_required" {
		t.Fatal("omitted policy field accepted")
	}
}
