//go:build linux && manager_lab

package launch

import "testing"

// Claim: the unmodified broker 9f1f90fa synthetic control reproduces seven independent frozen seals/digests, and changing its record format changes each digest without fixture resealing; this is arithmetic, not owner approval.
func TestLabStartFrozenDigests(test *testing.T) {
	cases := []struct {
		name, record, omit, domain, want string
	}{
		{"approval-seal", "approval", "approval", "swarma-broker-lab-approval-target/1", "sha256:a8e673fbf263e5c57c65344b5577833cb58a4eaf8651c5116346f0f6f4d29e8c"},
		{"release-seal", "release_set", "owner_approval", "swarma-broker-lab-approval-target/1", "sha256:bbb2a1fd963d669cccc58e3d6371c92a7f17b4c7131493dee58d4e702b6611ff"},
		{"invocation-target", "plan", "approval_record_sha256", "swarma-broker-lab-bounded-invocation-target/1", "sha256:2314d3bb80c1a484b87369c525fc895d38a8c894831faa7d816cce20f0e61daf"},
		{"approval-digest", "approval", "", "", "sha256:22807102ea5c04117c5ee3280b60e8892c75dc32988f3e5797be4f29faf1e041"},
		{"release-digest", "release_set", "", "", "sha256:bfdb63497a92b28aa28e52fc35b691a181dfd0155eb231896964f9e54c627db6"},
		{"invocation-digest", "plan", "", "", "sha256:cbd91903f5579cd00b420e4ed9af3fa8000fe76c9842306e0fdccfd84f3367ae"},
		{"launch-digest", "launch_plan", "", "", "sha256:3dab6bfca398f8632235dde701c3eacd35c21e8a197a5db7dbb01698b2e82cd1"},
	}
	for _, entry := range cases {
		test.Run(entry.name, func(test *testing.T) {
			record := labMap(labFixtureObject(test, labAdmissionFrozenCase), entry.record)
			digest := func() string {
				if entry.omit != "" {
					return labTarget(record, entry.omit, entry.domain)
				}
				return labObjectDigest(record)
			}
			if actual := digest(); actual != entry.want {
				test.Fatalf("frozen contract digest changed: got %s want %s", actual, entry.want)
			}
			format := record["format"]
			record["format"] = "fixture-other"
			if digest() == entry.want {
				test.Fatal("changed record retained its approved digest")
			}
			record["format"] = format
			if digest() != entry.want {
				test.Fatal("restored frozen digest control refused")
			}
		})
	}
}
