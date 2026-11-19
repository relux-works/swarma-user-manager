//go:build linux

package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

func mappingFixture(t *testing.T) (*fixture, launchMapping, Deps) {
	t.Helper()
	fixture := newFixture(t)
	fixture.installGate(fixture.gate())
	directory := filepath.Join(fixture.root, "etc/launch-mappings")
	mkdir(t, directory, 0755)
	socketDirectory := filepath.Join(fixture.root, "run/credential-gateway", "Gateway-1.a_b")
	mkdir(t, socketDirectory, 0755)
	dirFD, err := unix.Open(socketDirectory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dirFD)
	socketFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(socketFD) })
	if err := unix.Bind(socketFD, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/gateway.sock", dirFD)}); err != nil {
		t.Fatal(err)
	}
	mapping := launchMapping{
		Format: launchMappingFormat, ExecutorID: fixtureExecutor, ExecutorSHA256: digestOf([]byte("#!/bin/true\n")),
		Kind: "claude-gateway", GatewaySocket: filepath.Join(socketDirectory, "gateway.sock"),
		BaseURL: "http://api.anthropic.com", CredentialVariable: "CLAUDE_CODE_OAUTH_TOKEN", Placeholder: "ssh-placeholder", Network: "unix-only",
	}
	writeMappingObject(t, filepath.Join(directory, "index.json"), launchMappings{Format: launchMappingsFormat, Mapped: []string{fixtureExecutor}})
	writeMappingObject(t, filepath.Join(directory, fixtureExecutor+".json"), mapping)
	deps := fixture.deps()
	deps.Confine = func() error { return nil }
	return fixture, mapping, deps
}

func writeMappingObject(t *testing.T, path string, object any) {
	t.Helper()
	data, err := manager.ObjectBytes(object)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, data, 0644)
}

func mappingObject(t *testing.T, mapping launchMapping) map[string]any {
	t.Helper()
	data, err := json.Marshal(mapping)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func baseLaunchEnvironment(fixture *fixture) []string {
	return []string{"HOME=" + fixture.account.Home, "USER=worker-dev", "LOGNAME=worker-dev", "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "TMPDIR=" + fixture.account.Home + "/tmp"}
}

func assertNoMappingAdmission(t *testing.T, fixture *fixture) {
	t.Helper()
	if fixture.seams.execs != 0 || len(fixture.seams.drops) != 0 || fixture.seams.entered != 0 || fixture.seams.sessions != 0 || len(fixture.effects().Launches) != 0 || len(fixture.receipts()) != 0 || len(fixture.debits()) != 0 {
		t.Fatal("mapping refusal admitted a launch or changed durable evidence")
	}
}

// Claim: malformed index/schema/path/socket/pin state refuses before admission;
// each negative has a neighboring unchanged mapped or legacy control.
func TestLaunchMappingGates(t *testing.T) {
	type mutation func(*testing.T, *fixture, *launchMapping, *Deps)
	cases := []struct {
		name   string
		mutate mutation
		code   string
		legacy bool
	}{
		{name: "valid"},
		{name: "missing-directory", legacy: true, mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			if err := os.RemoveAll(filepath.Join(fixture.root, "etc/launch-mappings")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing-index", legacy: true, mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			if err := os.Remove(filepath.Join(fixture.root, "etc/launch-mappings/index.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "empty-index", legacy: true, mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings/index.json"), launchMappings{launchMappingsFormat, []string{}})
		}},
		{name: "unlisted", legacy: true, mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings/index.json"), launchMappings{launchMappingsFormat, []string{"another-worker"}})
			write(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), []byte("invalid unused mapping"), 0600)
		}},
		{name: "listed-missing-mapping", code: "launch_mapping_unavailable", mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			if err := os.Remove(filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "digest", code: "launch_mapping_digest_mismatch", mutate: func(_ *testing.T, _ *fixture, mapping *launchMapping, _ *Deps) {
			mapping.ExecutorSHA256 = strings.Repeat("a", 64)
		}},
		{name: "executable-pin-first", code: "executable_digest_mismatch", mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
			write(t, fixture.execPath, []byte("altered executable"), 0755)
			if err := os.Remove(filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "missing-socket", code: "launch_mapping_unavailable", mutate: func(t *testing.T, _ *fixture, mapping *launchMapping, _ *Deps) {
			if err := os.Remove(mapping.GatewaySocket); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "non-socket", code: "launch_mapping_unavailable", mutate: func(t *testing.T, _ *fixture, mapping *launchMapping, _ *Deps) {
			if err := os.Remove(mapping.GatewaySocket); err != nil {
				t.Fatal(err)
			}
			write(t, mapping.GatewaySocket, nil, 0600)
		}},
		{name: "socket-link", code: "launch_mapping_unavailable", mutate: func(t *testing.T, _ *fixture, mapping *launchMapping, _ *Deps) {
			if err := os.Rename(mapping.GatewaySocket, mapping.GatewaySocket+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(mapping.GatewaySocket+".real", mapping.GatewaySocket); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "socket-parent-link", code: "launch_mapping_unavailable", mutate: func(t *testing.T, _ *fixture, mapping *launchMapping, _ *Deps) {
			directory := filepath.Dir(mapping.GatewaySocket)
			if err := os.Rename(directory, directory+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(directory+".real", directory); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, target := range []string{"index.json", fixtureExecutor + ".json"} {
		for _, variant := range []string{"mode", "hardlink", "symlink", "directory", "fifo", "oversize", "unknown", "duplicate", "noncanonical"} {
			cases = append(cases, struct {
				name   string
				mutate mutation
				code   string
				legacy bool
			}{
				name: target + "-" + variant, code: "launch_mapping_invalid",
				mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
					path := filepath.Join(fixture.root, "etc/launch-mappings", target)
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					switch variant {
					case "mode":
						err = os.Chmod(path, 0664)
					case "hardlink":
						err = os.Link(path, path+".link")
					case "symlink":
						if err = os.Rename(path, path+".real"); err == nil {
							err = os.Symlink(path+".real", path)
						}
					case "directory", "fifo":
						if err = os.Remove(path); err == nil {
							if variant == "directory" {
								err = os.Mkdir(path, 0644)
							} else {
								err = unix.Mkfifo(path, 0644)
							}
						}
					case "oversize":
						write(t, path, bytes.Repeat([]byte(" "), manager.MaxRequest+1), 0644)
					case "unknown":
						write(t, path, append([]byte(`{"extra":true,`), data[1:]...), 0644)
					case "duplicate":
						write(t, path, append([]byte(`{"format":"duplicate",`), data[1:]...), 0644)
					case "noncanonical":
						write(t, path, append(data, []byte("\n")...), 0644)
					}
					if err != nil {
						t.Fatal(err)
					}
				},
			})
		}
	}
	for _, variant := range []string{"mode", "link", "file"} {
		cases = append(cases, struct {
			name   string
			mutate mutation
			code   string
			legacy bool
		}{
			name: "parent-" + variant, code: "launch_mapping_invalid", mutate: func(t *testing.T, fixture *fixture, _ *launchMapping, _ *Deps) {
				directory := filepath.Join(fixture.root, "etc/launch-mappings")
				var err error
				if variant == "mode" {
					err = os.Chmod(directory, 0775)
				} else {
					if err = os.Rename(directory, directory+".real"); err == nil {
						if variant == "link" {
							err = os.Symlink(directory+".real", directory)
						} else {
							write(t, directory, nil, 0644)
						}
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			},
		})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture, mapping, deps := mappingFixture(t)
			if test.mutate != nil {
				before := mapping
				test.mutate(t, fixture, &mapping, &deps)
				if mapping != before {
					writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), mapping)
				}
			}
			response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller))
			if test.code != "" {
				wantCode(t, response, test.code)
				assertNoMappingAdmission(t, fixture)
				return
			}
			if !response.OK || fixture.seams.execs != 1 {
				t.Fatalf("mapping control refused: %s", errCode(response))
			}
			want := baseLaunchEnvironment(fixture)
			if !test.legacy {
				want = append(want, mapping.environment()...)
			}
			if !reflect.DeepEqual(fixture.seams.env, want) {
				t.Fatal("mapping environment differs from fixed contract")
			}
		})
	}
}

// Claim: closed values, index ordering and generation grammar have positive
// neighbors; no malformed representation is accepted merely by decoding JSON.
func TestLaunchMappingClosedValues(t *testing.T) {
	for field, invalid := range map[string]any{
		"format": "station-launch-mapping/2", "executor_id": "other-executor", "executor_sha256": "invalid", "kind": "other",
		"base_url": "https://api.anthropic.com", "credential_variable": "ANTHROPIC_API_KEY", "placeholder": "other", "network": "any",
	} {
		t.Run(field, func(t *testing.T) {
			fixture, mapping, deps := mappingFixture(t)
			object := mappingObject(t, mapping)
			object[field] = invalid
			writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), object)
			wantCode(t, (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)), "launch_mapping_invalid")
			assertNoMappingAdmission(t, fixture)
			writeMappingObject(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), mapping)
			if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)); !response.OK {
				t.Fatal("closed-value control refused", errCode(response))
			}
		})
	}
	for name, object := range map[string]any{
		"format":         launchMappings{"other", []string{fixtureExecutor}},
		"null":           launchMappings{launchMappingsFormat, nil},
		"unsorted":       launchMappings{launchMappingsFormat, []string{fixtureExecutor, "a"}},
		"duplicate":      launchMappings{launchMappingsFormat, []string{fixtureExecutor, fixtureExecutor}},
		"invalid-id":     launchMappings{launchMappingsFormat, []string{"../other"}},
		"missing-member": map[string]any{"format": launchMappingsFormat},
	} {
		t.Run("index-"+name, func(t *testing.T) {
			fixture, _, deps := mappingFixture(t)
			path := filepath.Join(fixture.root, "etc/launch-mappings/index.json")
			writeMappingObject(t, path, object)
			wantCode(t, (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)), "launch_mapping_invalid")
			assertNoMappingAdmission(t, fixture)
			writeMappingObject(t, path, launchMappings{launchMappingsFormat, []string{"a", fixtureExecutor, "z"}})
			if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)); !response.OK {
				t.Fatal("index control refused", errCode(response))
			}
		})
	}
	for _, generation := range []string{"A", "0", "Gateway-1.a_b", "a" + strings.Repeat("z", 127)} {
		fixture, mapping, _ := mappingFixture(t)
		mapping.GatewaySocket = fixture.root + "/run/credential-gateway/" + generation + "/gateway.sock"
		if !mapping.valid(fixture.root, fixtureExecutor) {
			t.Fatal("valid generation refused")
		}
	}
	for _, generation := range []string{"", ".", "..", "_a", "-a", "a/b", "a/../b", "a%2fb", "a\nb", strings.Repeat("a", 129)} {
		t.Run("generation-"+fmt.Sprintf("%x", generation), func(t *testing.T) {
			fixture, mapping, _ := mappingFixture(t)
			mapping.GatewaySocket = fixture.root + "/run/credential-gateway/" + generation + "/gateway.sock"
			if mapping.valid(fixture.root, fixtureExecutor) {
				t.Fatal("invalid generation admitted")
			}
		})
	}
	t.Run("socket-root-and-suffix", func(t *testing.T) {
		fixture, mapping, _ := mappingFixture(t)
		for _, path := range []string{"relative/gateway.sock", mapping.GatewaySocket + "/extra", mapping.GatewaySocket + "/../gateway.sock", "/other/run/credential-gateway/a/gateway.sock", strings.Replace(mapping.GatewaySocket, "/run/", "//run/", 1)} {
			mapping.GatewaySocket = path
			if mapping.valid(fixture.root, fixtureExecutor) {
				t.Fatal("invalid socket path admitted")
			}
		}
	})
}

// Claim: real fstat controls pass; independently altered ownership, group, type,
// mode and link fields refuse. Ownership negatives are metadata fixtures, not
// evidence of installing a root-owned deployment from an unprivileged runner.
func TestLaunchMappingMetadata(t *testing.T) {
	fixture, _, _ := mappingFixture(t)
	for _, directory := range []bool{false, true} {
		name := "index.json"
		if directory {
			name = "."
		}
		file, err := os.Open(filepath.Join(fixture.root, "etc/launch-mappings", name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		var valid unix.Stat_t
		if unix.Fstat(int(file.Fd()), &valid) != nil || mappingMetadata(file, fixture.owner, directory) != nil {
			t.Fatal("metadata control refused")
		}
		for name, mutate := range map[string]func(*unix.Stat_t){
			"owner": func(stat *unix.Stat_t) { stat.Uid++ }, "group": func(stat *unix.Stat_t) { stat.Gid++ },
			"mode": func(stat *unix.Stat_t) { stat.Mode ^= 0001 }, "special-mode": func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISUID },
			"type":  func(stat *unix.Stat_t) { stat.Mode = stat.Mode&07777 | unix.S_IFIFO },
			"links": func(stat *unix.Stat_t) { stat.Nlink++ },
		} {
			if directory && name == "links" {
				continue
			}
			t.Run(fmt.Sprintf("%t-%s", directory, name), func(t *testing.T) {
				altered := valid
				mutate(&altered)
				if checkMappingStat(altered, fixture.owner, directory) == nil {
					t.Fatal("unsafe mapping metadata admitted")
				}
				if checkMappingStat(valid, fixture.owner, directory) != nil {
					t.Fatal("metadata control refused")
				}
			})
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if mappingMetadata(file, fixture.owner, directory) == nil {
			t.Fatal("failed fstat admitted")
		}
	}
}

// Claim: the descriptor reader returns bounded bytes for a valid file and
// refuses an oversized file before any consumer can interpret truncated data.
func TestLaunchMappingReadBound(t *testing.T) {
	fixture, _, _ := mappingFixture(t)
	directory, err := os.Open(filepath.Join(fixture.root, "etc/launch-mappings"))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if _, err := readMappingFile(directory, "index.json", fixture.owner); err != nil {
		t.Fatal("bounded read control refused", err)
	}
	write(t, filepath.Join(fixture.root, "etc/launch-mappings/index.json"), bytes.Repeat([]byte(" "), manager.MaxRequest+1), 0644)
	data, err := readMappingFile(directory, "index.json", fixture.owner)
	if code(err) != "launch_mapping_invalid" || data != nil {
		t.Fatal("oversized mapping read admitted")
	}
}

// Claim: inherited model variables and launch-op environment fields cannot
// supply worker values; mapped output and receipts have exact fixed bytes.
func TestLaunchMappingEnvironmentAndOrdering(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_UNIX_SOCKET", "ANTHROPIC_UNLISTED", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_UNLISTED", "DISABLE_TELEMETRY", "EXTRA_CALLER_VALUE"} {
		t.Setenv(name, "caller-marker")
	}
	t.Run("valid", func(t *testing.T) {
		fixture, mapping, deps := mappingFixture(t)
		order := []string{}
		originalDrop, originalExec := deps.Drop, deps.Exec
		deps.Drop = func(uid, gid uint32) error {
			if len(fixture.receipts()) != 1 {
				t.Fatal("drop before durable receipt")
			}
			order = append(order, "drop")
			return originalDrop(uid, gid)
		}
		deps.Confine = func() error {
			if !reflect.DeepEqual(order, []string{"drop"}) || len(fixture.debits()) != 1 {
				t.Fatal("confinement before drop or committed start")
			}
			order = append(order, "confine")
			return nil
		}
		deps.Exec = func(fd int, argv, env []string) error {
			if !reflect.DeepEqual(order, []string{"drop", "confine"}) {
				t.Fatal("exec before confinement")
			}
			want := append(baseLaunchEnvironment(fixture),
				"ANTHROPIC_UNIX_SOCKET="+mapping.GatewaySocket, "ANTHROPIC_BASE_URL=http://api.anthropic.com", "CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder",
				"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_TELEMETRY=1", "DISABLE_ERROR_REPORTING=1", "DISABLE_AUTOUPDATER=1", "DISABLE_UPDATES=1")
			if !reflect.DeepEqual(env, want) {
				t.Fatal("worker environment is not the exact fixed set")
			}
			return originalExec(fd, argv, env)
		}
		if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)); !response.OK {
			t.Fatal("environment control refused", errCode(response))
		}
		assertReceiptBytes(t, fixture)
	})
	for _, name := range []string{"missing-confinement", "failed-confinement", "input-environment"} {
		t.Run(name, func(t *testing.T) {
			fixture, _, deps := mappingFixture(t)
			request := fixture.launchRequest("launch-1", nil)
			code := "launch_confinement_unavailable"
			if name == "missing-confinement" {
				deps.Confine = nil
			} else if name == "failed-confinement" {
				deps.Confine = func() error { return unix.EPERM }
			} else {
				code = "request_invalid"
				request = fixture.launchRequest("launch-1", map[string]any{"env": map[string]any{"ANTHROPIC_API_KEY": "caller-marker"}})
			}
			wantCode(t, (Launcher{deps}).Run(context.Background(), request, fixture.invocation(fixture.caller)), code)
			if fixture.seams.execs != 0 {
				t.Fatal("refusal reached exec")
			}
			if name == "input-environment" {
				assertNoMappingAdmission(t, fixture)
			} else {
				if len(fixture.receipts()) != 1 || len(fixture.debits()) != 1 {
					t.Fatal("confinement refusal lost attempted-start evidence")
				}
				assertReceiptBytes(t, fixture)
			}
		})
	}
}

func assertReceiptBytes(t *testing.T, fixture *fixture) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.root, "lib/user-manager/receipts", fixtureGen, "EX-1.json"))
	want := fmt.Sprintf(`{"boot_id":"%s","epoch":3,"execution_id":"EX-1","pid":%d,"session_id":4242,"start_time":7}`, fixtureBoot, os.Getpid())
	if err != nil || string(data) != want {
		t.Fatal("receipt bytes changed", err)
	}
}

// Claim: absent selection and an unlisted executor ignore mapping bytes, invoke
// no confinement and retain the original environment, argv and receipt bytes.
func TestLaunchMappingUnlistedBytes(t *testing.T) {
	for _, variant := range []string{"absent", "unlisted"} {
		t.Run(variant, func(t *testing.T) {
			fixture, _, deps := mappingFixture(t)
			index := filepath.Join(fixture.root, "etc/launch-mappings/index.json")
			if variant == "absent" {
				if err := os.Remove(index); err != nil {
					t.Fatal(err)
				}
			} else {
				writeMappingObject(t, index, launchMappings{launchMappingsFormat, []string{"other"}})
			}
			deps.Confine = func() error { t.Fatal("legacy launch was confined"); return unix.EPERM }
			write(t, filepath.Join(fixture.root, "etc/launch-mappings", fixtureExecutor+".json"), []byte("ignored"), 0600)
			if response := (Launcher{deps}).Run(context.Background(), fixture.launchRequest("launch-1", nil), fixture.invocation(fixture.caller)); !response.OK {
				t.Fatal("legacy control refused", errCode(response))
			}
			if !reflect.DeepEqual(fixture.seams.env, baseLaunchEnvironment(fixture)) || !reflect.DeepEqual(fixture.seams.argv, []string{fixture.execPath}) {
				t.Fatal("legacy exec bytes changed")
			}
			assertReceiptBytes(t, fixture)
		})
	}
}
