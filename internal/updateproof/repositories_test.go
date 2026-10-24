package updateproof

import (
	"context"
	"crypto/md5"
	"fmt"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"strings"
	"testing"
	"time"
)

// Claim: two packages in one invocation can authenticate to different approved
// suites without sharing release frontiers or dropping a source. Unknown,
// swapped, missing and replayed source proofs refuse without partial evidence.
func TestUpdateMultipleRepositoryChains(t *testing.T) {
	f := newSignedFixture(t)
	p := RepositoryProfile{Common: f.profile, Repositories: []Repository{{"updates", f.profile.Origin, f.profile.Suite, f.profile.Codename, f.profile.IndexPath}, {"security", f.profile.Origin, "fixture-security", f.profile.Codename, f.profile.IndexPath}}}
	p.Common.Mappings = append(p.Common.Mappings, Mapping{Path: "/usr/lib/companion", Package: "companion", Architecture: "amd64", Mode: 0644})
	data := []byte("second authenticated leaf\n")
	archive := makeDebAt(t, "companion", "2", "amd64", data, "usr/lib/companion")
	before := Package{Name: "companion", Version: "1", Architecture: "amd64", Status: "installed", ArchiveSHA256: Digest([]byte("old companion archive"))}
	after := before
	after.Version = "2"
	after.ArchiveSHA256 = Digest(archive)
	oldLeaf := Leaf{Path: "/usr/lib/companion", Package: "companion", Architecture: "amd64", SHA256: Digest([]byte("old companion")), Mode: 0644}
	newLeaf := oldLeaf
	newLeaf.SHA256 = Digest(data)
	inv := f.inv
	inv.Before.Packages = append([]Package{before}, inv.Before.Packages...)
	inv.After.Packages = append([]Package{after}, inv.After.Packages...)
	inv.Before.Leaves = append([]Leaf{oldLeaf}, inv.Before.Leaves...)
	inv.After.Leaves = append([]Leaf{newLeaf}, inv.After.Leaves...)
	base := RepositoryBaseline{Common: f.baseline, Releases: map[string]ReleaseWatermark{"updates": {f.baseline.ReleaseDate, f.baseline.ReleaseSHA256}, "security": {f.baseline.ReleaseDate, f.baseline.ReleaseSHA256}}}
	base.Common.Packages = append([]Package{before}, base.Common.Packages...)
	base.Common.Leaves = append([]Leaf{oldLeaf}, base.Common.Leaves...)
	first := f.bundle
	index := []byte(fmt.Sprintf("Package: companion\nVersion: 2\nArchitecture: amd64\nFilename: pool/main/c/companion.deb\nSize: %d\nSHA256: %s\n\n", len(archive), Digest(archive)))
	f.release = strings.Replace(f.release, "Suite: fixture-updates", "Suite: fixture-security", 1)
	f.release = strings.Replace(f.release, fmt.Sprintf("%s %d %s", Digest(first.Index), len(first.Index), f.profile.IndexPath), fmt.Sprintf("%s %d %s", Digest(index), len(index), f.profile.IndexPath), 1)
	f.sign(false)
	second := Bundle{Release: f.bundle.Release, Signature: f.bundle.Signature, Index: index, Archives: map[string][]byte{"companion:amd64": archive}, Installed: map[string]Installed{"/usr/lib/companion": {Bytes: data, Mode: 0644, MD5: fmt.Sprintf("%x", md5.Sum(data))}}}
	bundle := RepositoryBundle{Sources: map[string]Bundle{"updates": first, "security": second}, SourceByPackage: map[string]string{"fixture:amd64": "updates", "companion:amd64": "security"}}
	source := sampleSource{s: timeconf.Sample{Now: f.clock.Now, AuthorityUntil: f.clock.Now.Add(time.Minute), Trusted: true, Fresh: true, Boot: inv.ID.Boot}}
	ctx := context.Background()
	check := func() {
		t.Helper()
		ev, e := VerifyRepositories(ctx, p, base, inv, bundle, source)
		if e != nil || len(ev.Parts) != 2 {
			t.Fatal("two-source control", e, ev)
		}
		for _, part := range ev.Parts {
			if part.TransactionSHA256 != ev.TransactionSHA256 {
				t.Fatal("subset transaction binding")
			}
		}
	}
	check()
	bundle.SourceByPackage["companion:amd64"] = "unapproved"
	if _, e := VerifyRepositories(ctx, p, base, inv, bundle, source); e != ErrScope {
		t.Fatal("source discovered from update", e)
	}
	bundle.SourceByPackage["companion:amd64"] = "security"
	delete(bundle.Sources, "security")
	if _, e := VerifyRepositories(ctx, p, base, inv, bundle, source); e != ErrMissing {
		t.Fatal("missing source omitted", e)
	}
	bundle.Sources["security"] = second
	bundle.SourceByPackage["fixture:amd64"] = "security"
	bundle.SourceByPackage["companion:amd64"] = "updates"
	if _, e := VerifyRepositories(ctx, p, base, inv, bundle, source); e != ErrScope {
		t.Fatal("swapped source attribution", e)
	}
	bundle.SourceByPackage["fixture:amd64"] = "updates"
	bundle.SourceByPackage["companion:amd64"] = "security"
	saved := base.Releases["security"]
	base.Releases["security"] = ReleaseWatermark{f.clock.Now, Digest([]byte("later security release"))}
	if _, e := VerifyRepositories(ctx, p, base, inv, bundle, source); e != ErrTime {
		t.Fatal("per-source replay", e)
	}
	base.Releases["security"] = saved
	check()
	if _, e := VerifyRepositoryBatch(ctx, p, base, Batch{ID: inv.ID, Invocations: []Invocation{inv}}, map[ID]RepositoryBundle{inv.ID: bundle}, source); e != nil {
		t.Fatal("batch control", e)
	}
}
