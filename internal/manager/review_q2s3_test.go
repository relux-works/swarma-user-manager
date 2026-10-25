//go:build linux

package manager

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Claim: PreparedEvidence must retain the capture-vector identities promised by
// the accepted plan. Two stable captures with identical bytes but distinct root
// inodes must not produce identical evidence. Only an isolated fixture is changed.
func TestReviewQ2S3EvidenceHeadIdentity(t *testing.T) {
	f := newCensusFixture(t, censusOptions{})
	first := censusValid(t, f.c)
	target := f.c.targets[0]
	a, err := target.Directory.Read(target.Name, 0640, target.Cap)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "auth", target.Name)
	censusWrite(t, path+".new", a.Bytes(), 0640)
	if err = os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	censusSyncDir(t, filepath.Dir(path))
	b, err := target.Directory.Read(target.Name, 0640, target.Cap)
	if err != nil || a.Identity == b.Identity || a.Digest != b.Digest {
		t.Fatal("identity-only fixture change not established", a.Identity, b.Identity, err)
	}
	before := censusTreeBytes(t, f.root)
	second := censusValid(t, f.c)
	censusSameTree(t, before, censusTreeBytes(t, f.root))
	if !bytes.Equal(first.ClassBytes("inventory"), second.ClassBytes("inventory")) {
		t.Fatal("changed unrelated inventory")
	}
	if bytes.Equal(first.EvidenceBytes(), second.EvidenceBytes()) {
		t.Fatalf("prepared evidence erased captured root identity: before=%v after=%v evidence=%s", a.Identity, b.Identity, first.EvidenceBytes())
	}
}
