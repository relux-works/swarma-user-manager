//go:build linux

package linuxbackend

import (
	"encoding/json"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// Service roots are a closed, sorted path list, with all three mandatory roots
// present. Extra reviewed load paths are allowed; legacy content/state objects,
// invalid paths, unknown fields and missing required roots cannot grant scope.
func TestQualificationServiceRootSchema(t *testing.T) {
	for _, mode := range []string{"valid", "extra-load-path", "missing-etc", "missing-run", "missing-usr", "empty", "null", "relative", "duplicate", "unordered", "old-pin", "unknown-field"} {
		t.Run(mode, func(t *testing.T) {
			m := manifestFixture()
			p, _ := fixture()
			switch mode {
			case "extra-load-path":
				m.NoLauncher.ServiceRoots = []string{"/etc/systemd/system", "/run/systemd/generator", "/run/systemd/system", "/run/systemd/transient", "/usr/lib/systemd/system"}
			case "missing-etc":
				m.NoLauncher.ServiceRoots = m.NoLauncher.ServiceRoots[1:]
			case "missing-run":
				m.NoLauncher.ServiceRoots = []string{"/etc/systemd/system", "/usr/lib/systemd/system"}
			case "missing-usr":
				m.NoLauncher.ServiceRoots = m.NoLauncher.ServiceRoots[:2]
			case "empty":
				m.NoLauncher.ServiceRoots = []string{}
			case "null":
				m.NoLauncher.ServiceRoots = nil
			case "relative":
				m.NoLauncher.ServiceRoots[0] = "relative"
			case "duplicate":
				m.NoLauncher.ServiceRoots = append(m.NoLauncher.ServiceRoots, m.NoLauncher.ServiceRoots[2])
			case "unordered":
				m.NoLauncher.ServiceRoots[0], m.NoLauncher.ServiceRoots[1] = m.NoLauncher.ServiceRoots[1], m.NoLauncher.ServiceRoots[0]
			}
			raw, e := qualification.Canonical(m)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "old-pin" || mode == "unknown-field" {
				var doc map[string]any
				if e = json.Unmarshal(raw, &doc); e != nil {
					t.Fatal(e)
				}
				n := doc["no_launcher"].(map[string]any)
				if mode == "old-pin" {
					n["service_roots"] = []any{map[string]any{"path": "/etc/systemd/system", "state": "present", "digest": m.BackendFiles[0].Digest}}
				} else {
					n["digest"] = m.BackendFiles[0].Digest
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
			if mode == "valid" || mode == "extra-load-path" {
				if e != nil {
					t.Fatal("valid service path schema", e)
				}
			} else if e == nil {
				t.Fatal("invalid scope admitted")
			}
		})
	}
}

// Provider configuration capabilities are closed typed paths. All five manager
// file/drop-in roots can be expressed, including absent directories; legacy
// strings, omitted/unknown kinds, unknown members and duplicate paths refuse.
func TestQualificationProviderConfigurationSchema(t *testing.T) {
	for _, mode := range []string{"valid", "unknown-kind", "missing-kind", "nil", "duplicate", "relative", "legacy-string", "extra-field"} {
		t.Run(mode, func(t *testing.T) {
			m := manifestFixture()
			p, _ := fixture()
			m.Systemd = &SystemdProfile{Library: "/usr/lib/libnss_systemd.so.2", Providers: []SystemdProviderProfile{{Name: "io.systemd.DynamicUser", Implementation: []string{"/usr/lib/systemd/systemd"}, Configuration: []ConfigurationPath{
				{Kind: "file", Path: "/etc/systemd/system.conf"},
				{Kind: "absent", Path: "/etc/systemd/system.conf.d"},
				{Kind: "absent", Path: "/run/systemd/system.conf.d"},
				{Kind: "directory", Path: "/usr/lib/systemd/system.conf.d"},
				{Kind: "absent", Path: "/usr/local/lib/systemd/system.conf.d"},
			}}}, Sources: []SystemdSourceProfile{{URL: "https://systemd.io/UIDS-GIDS/", Path: "/opt/swarma/etc/range-source.txt"}}}
			c := &m.Systemd.Providers[0].Configuration
			switch mode {
			case "unknown-kind":
				(*c)[0].Kind = "optional"
			case "missing-kind":
				(*c)[0].Kind = ""
			case "nil":
				*c = nil
			case "duplicate":
				*c = append(*c, (*c)[0])
			case "relative":
				(*c)[0].Path = "relative"
			}
			raw, e := qualification.Canonical(m)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "legacy-string" || mode == "extra-field" {
				var doc map[string]any
				if e = json.Unmarshal(raw, &doc); e != nil {
					t.Fatal(e)
				}
				provider := doc["systemd"].(map[string]any)["providers"].([]any)[0].(map[string]any)
				if mode == "legacy-string" {
					provider["configuration"] = []any{"/etc/systemd/system.conf"}
				} else {
					provider["configuration"].([]any)[0].(map[string]any)["digest"] = "unexpected"
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
					t.Fatal("valid typed manager configuration", e)
				}
			} else if e == nil {
				t.Fatal("invalid typed configuration admitted")
			}
		})
	}
}
