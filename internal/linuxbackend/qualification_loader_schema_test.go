//go:build linux

package linuxbackend

import (
	"encoding/json"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// The changed closed loader schema requires explicit ordered context/evidence;
// missing arrays, unreviewed paths, invalid shapes and legacy tree pins refuse.
func TestQualificationLoaderSchema(t *testing.T) {
	for _, mode := range []string{"legacy-tree", "unknown-location", "missing-runpath", "missing-locations", "missing-links", "relative-default", "token-default", "duplicate-default", "missing-default", "bad-cache-miss", "early-hit", "duplicate-resolution", "absolute-scope", "valid"} {
		t.Run(mode, func(t *testing.T) {
			m := manifestFixture()
			p, _ := fixture()
			r := &m.Loader.Resolutions[0]
			switch mode {
			case "missing-runpath":
				r.Runpath = nil
			case "missing-locations":
				r.Locations = nil
			case "missing-links":
				r.Locations[0].Links = nil
			case "relative-default":
				m.Loader.DefaultDirectories = []string{"relative"}
			case "token-default":
				m.Loader.DefaultDirectories = []string{"/$LIB"}
			case "duplicate-default":
				m.Loader.DefaultDirectories = []string{"/usr/lib", "/usr/lib"}
			case "missing-default":
				m.Loader.DefaultDirectories = nil
			case "bad-cache-miss":
				r.Locations[0].State = "miss"
			case "early-hit":
				r.Locations = append(r.Locations, r.Locations[0])
			case "duplicate-resolution":
				m.Loader.Resolutions = append(m.Loader.Resolutions, *r)
			case "absolute-scope":
				r.Name = "/usr/lib/libc.so.6"
				r.Runpath = []string{"/usr/lib"}
			}
			raw, e := qualification.Canonical(m)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "legacy-tree" || mode == "unknown-location" {
				var doc map[string]any
				if e = json.Unmarshal(raw, &doc); e != nil {
					t.Fatal(e)
				}
				loader := doc["loader"].(map[string]any)
				if mode == "legacy-tree" {
					loader["search_roots"] = []any{}
				} else {
					loader["resolutions"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["unknown"] = true
				}
				raw, e = json.Marshal(doc)
				if e != nil {
					t.Fatal(e)
				}
			}
			p.BackendDigest = qualification.Hash(raw)
			var parsed DeploymentManifest
			e = qualification.DecodeClosed(raw, &parsed, 65536)
			if e == nil {
				e = parsed.validate(p)
			}
			if mode == "valid" {
				if e != nil {
					t.Fatal("valid schema refused", e)
				}
			} else if e == nil {
				t.Fatal("invalid loader schema admitted")
			}
		})
	}
}
