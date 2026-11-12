//go:build linux

package slotd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const installUnitName = "swarma-slotd-demo.service"

// removeLater removes a fixture-planted path at cleanup; a test may already
// have removed it on purpose.
func removeLater(t *testing.T, path string) {
	t.Cleanup(func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Error(err)
		}
	})
}

// ensureDirs creates each missing component of path as root:root 0755 and
// removes only those components again at cleanup (innermost first).
func ensureDirs(t *testing.T, path string) {
	t.Helper()
	current := "/"
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		current = filepath.Join(current, part)
		if _, err := os.Lstat(current); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := unix.Mkdir(current, 0700); err != nil {
			t.Fatal(err)
		}
		removeLater(t, current)
		if err := unix.Chmod(current, 0755); err != nil {
			t.Fatal(err)
		}
	}
}

func plantDir(t *testing.T, path string, mode uint32) {
	t.Helper()
	ensureDirs(t, filepath.Dir(path))
	if err := unix.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	removeLater(t, path)
	if err := unix.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func plantFile(t *testing.T, path string, b []byte, mode uint32) {
	t.Helper()
	ensureDirs(t, filepath.Dir(path))
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	removeLater(t, path)
	_, err = out.Write(b)
	if err = errors.Join(err, out.Close()); err != nil {
		t.Fatal(err)
	}
	if err = unix.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func plantSymlink(t *testing.T, target, path string) {
	t.Helper()
	ensureDirs(t, filepath.Dir(path))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	removeLater(t, path)
}

func daemonReload(t *testing.T) {
	t.Helper()
	if _, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "daemon-reload"}}); err != nil {
		t.Fatal(err)
	}
}

// loadedUnitProperties is systemd's own report of the loaded unit, read
// independently of the installer.
func loadedUnitProperties(t *testing.T) map[string]string {
	t.Helper()
	b, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "show",
		"--property=LoadState,FragmentPath,DropInPaths,SourcePath,Names,UnitFileState,ActiveState", "--", installUnitName}})
	if err != nil {
		t.Fatal(err)
	}
	props := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		key, value, _ := strings.Cut(line, "=")
		props[key] = value
	}
	return props
}

// requireLoadedReviewed: systemd loaded exactly the reviewed fragment, with no
// drop-in, generator source or alias, and the unit is neither started nor enabled.
func requireLoadedReviewed(t *testing.T) {
	t.Helper()
	props := loadedUnitProperties(t)
	if props["LoadState"] != "loaded" || props["FragmentPath"] != installUnitPath || props["DropInPaths"] != "" || props["SourcePath"] != "" ||
		props["Names"] != installUnitName || props["UnitFileState"] != "disabled" || props["ActiveState"] != "inactive" {
		t.Fatalf("loaded unit is not the reviewed package: %q", props)
	}
}

// refuseBoth requires --check and apply to refuse with want before publishing:
// every watched object stays unchanged and every other target stays absent.
func (f *installFixture) refuseBoth(t *testing.T, name, want string, setup func(t *testing.T) []string) {
	t.Run(name, func(t *testing.T) {
		f.absent(t)
		watched := setup(t)
		before := map[string]objectSnapshot{}
		for _, path := range watched {
			before[path] = snapshotObject(t, path)
		}
		for _, args := range [][]string{f.checkArgs, f.baseArgs} {
			f.invoke(t, args, "slotd install refused: "+want, false)
			requireUnchanged(t, before, "refused install")
			f.absent(t, watched...)
		}
	})
}

// mutantApplyArgs is mutantCheckArgs without --check, for mutants of what only
// apply mode runs (the post-reload checks).
func (f *installFixture) mutantApplyArgs(t *testing.T, name, old, replacement string) []string {
	t.Helper()
	args := f.mutantCheckArgs(t, name, old, replacement)
	return args[:len(args)-1]
}

const fixtureGenerator = "/etc/systemd/system-generators/slotd-fixture-generator"

// plantGenerator installs a system generator that every daemon-reload runs. At
// cleanup it is removed and systemd reloaded, so its output in
// /run/systemd/generator cannot outlive the subtest.
func plantGenerator(t *testing.T, body string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "daemon-reload"}}); err != nil {
			t.Error(err)
		}
	})
	plantFile(t, fixtureGenerator, []byte("#!/bin/sh\nset -eu\n"+body), 0755)
}

// unitDependencies is systemd's own report of one dependency property of the
// loaded unit, such as Wants or WantedBy.
func unitDependencies(t *testing.T, property string) []string {
	t.Helper()
	b, err := runFixedTool(context.Background(), toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "show",
		"--property=" + property, "--value", "--", installUnitName}})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(b))
}

// mutantCheckArgs stages, beside the real package files, a copy of the packaged
// installer with exactly one narrowing substitution, and returns --check args
// that run it instead of the real installer.
func (f *installFixture) mutantCheckArgs(t *testing.T, name, old, replacement string) []string {
	t.Helper()
	b, err := os.ReadFile(f.baseArgs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), old) != 1 {
		t.Fatalf("mutant %s anchor is not unique in the packaged installer", name)
	}
	path := filepath.Join(filepath.Dir(f.baseArgs[0]), "mutant-"+name+".py")
	writeInstallFile(t, path, []byte(strings.Replace(string(b), old, replacement, 1)), 0755)
	args := slices.Clone(f.checkArgs)
	args[0] = path
	return args
}

const overrideDropIn = "[Service]\nExecStart=\nExecStart=/usr/bin/true\n"

// Proves the installer closes the unit's effective systemd configuration before
// publication. In both --check and apply mode it refuses, with nothing written
// and every planted object unchanged: dash-prefix and type-wide drop-ins,
// persistent and runtime control drop-ins, units and drop-ins in the transient,
// attached, generator and local vendor load paths, an alias symlink, the unit's
// own and type-wide dependency directories and an enablement link. Valid
// neighbours: drop-ins for names systemd does not merge into this unit pass
// --check and a full install, after which systemd itself reports the reviewed
// fragment and no drop-in. A drop-in that a generator creates only at
// daemon-reload is refused by the post-reload readback (published files are
// retained, never started or enabled), then by the pre-publication scan, and an
// idempotent rerun verifies the unit once the generator is gone. A dependency
// a generator creates only at that reload (the unit's own .wants, .requires
// and .upholds and a dash-prefix .wants) is loaded by systemd yet refused by
// the post-reload namespace scan, and a generated reverse .wants link by the
// readback, with the same retained-files, no-start recovery; a generator whose dependency directories
// systemd does not merge into this unit is accepted. Narrowing mutants that
// omit one prefix or the type-wide scope, or whose post-reload scan omits the
// dependency directories or only their suffixes, admit the planted case.
// Hosted runner only; systemd semantics are those of its systemd version.
func TestRootInstallUnitNamespace(t *testing.T) {
	f := newInstallFixture(t)
	f.invoke(t, f.checkArgs, "no files published", true)
	f.absent(t)
	const refused = "additional or overridden daemon unit refused"
	dropIn := func(dir, content string) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			plantDir(t, dir, 0755)
			plantFile(t, filepath.Join(dir, "override.conf"), []byte(content), 0644)
			return []string{dir, filepath.Join(dir, "override.conf")}
		}
	}
	unitFile := func(path string) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			plantFile(t, path, f.expected[installUnitPath].data, 0644)
			return []string{path}
		}
	}
	for _, c := range []struct {
		name  string
		setup func(t *testing.T) []string
	}{
		{"prefix_dropin", dropIn("/etc/systemd/system/swarma-.service.d", overrideDropIn)},
		{"inner_prefix_dropin", dropIn("/etc/systemd/system/swarma-slotd-.service.d", overrideDropIn)},
		{"vendor_prefix_dropin", dropIn("/usr/lib/systemd/system/swarma-.service.d", overrideDropIn)},
		// Type-wide drop-ins apply to every service; the planted one is inert.
		{"global_dropin", dropIn("/etc/systemd/system/service.d", "[Service]\nEnvironment=SLOTD_NAMESPACE_FIXTURE=1\n")},
		{"runtime_global_dropin", dropIn("/run/systemd/system/service.d", "[Service]\nEnvironment=SLOTD_NAMESPACE_FIXTURE=1\n")},
		{"control_dropin", dropIn("/etc/systemd/system.control/swarma-slotd-demo.service.d", overrideDropIn)},
		{"runtime_control_dropin", dropIn("/run/systemd/system.control/swarma-slotd-demo.service.d", overrideDropIn)},
		{"transient_unit", unitFile("/run/systemd/transient/" + installUnitName)},
		{"attached_unit", unitFile("/etc/systemd/system.attached/" + installUnitName)},
		{"generator_unit", unitFile("/run/systemd/generator/" + installUnitName)},
		{"generator_early_dropin", dropIn("/run/systemd/generator.early/swarma-slotd-demo.service.d", overrideDropIn)},
		{"generator_late_dropin", dropIn("/run/systemd/generator.late/swarma-slotd-demo.service.d", overrideDropIn)},
		{"local_vendor_dropin", dropIn("/usr/local/lib/systemd/system/swarma-slotd-demo.service.d", overrideDropIn)},
		{"alias_symlink", func(t *testing.T) []string {
			plantSymlink(t, installUnitPath, "/etc/systemd/system/swarma-slotd-alias.service")
			return []string{"/etc/systemd/system/swarma-slotd-alias.service"}
		}},
		{"unit_wants_dir", func(t *testing.T) []string {
			plantDir(t, "/etc/systemd/system/swarma-slotd-demo.service.wants", 0755)
			return []string{"/etc/systemd/system/swarma-slotd-demo.service.wants"}
		}},
		{"global_requires_dir", func(t *testing.T) []string {
			plantDir(t, "/etc/systemd/system/service.requires", 0755)
			return []string{"/etc/systemd/system/service.requires"}
		}},
		{"enablement_link", func(t *testing.T) []string {
			link := "/etc/systemd/system/multi-user.target.wants/" + installUnitName
			plantSymlink(t, installUnitPath, link)
			return []string{link}
		}},
	} {
		f.refuseBoth(t, c.name, refused, c.setup)
	}

	// Each mutant narrows the scan by one namespace; the real installer refuses
	// the same planted state, so the named case above kills the mutant.
	for _, m := range []struct {
		name, old, replacement, killer string
		setup                          func(t *testing.T) []string
	}{
		{"prefix_scope_omitted", `"swarma-slotd-.service", "swarma-.service", "service")`, `"swarma-slotd-.service", "service")`,
			"prefix_dropin", dropIn("/etc/systemd/system/swarma-.service.d", overrideDropIn)},
		{"type_scope_omitted", `"swarma-slotd-.service", "swarma-.service", "service")`, `"swarma-slotd-.service", "swarma-.service")`,
			"global_dropin", dropIn("/etc/systemd/system/service.d", "[Service]\nEnvironment=SLOTD_NAMESPACE_FIXTURE=1\n")},
	} {
		t.Run("mutant_"+m.name+"_killed_by_"+m.killer, func(t *testing.T) {
			f.absent(t)
			mutant := f.mutantCheckArgs(t, m.name, m.old, m.replacement)
			m.setup(t)
			f.invoke(t, f.checkArgs, "slotd install refused: "+refused, false)
			f.invoke(t, mutant, "no files published", true)
			f.absent(t)
		})
	}

	// Valid neighbours: systemd merges none of these names into this unit.
	t.Run("unrelated_names_accepted", func(t *testing.T) {
		f.absent(t)
		for _, dir := range []string{"/etc/systemd/system/swarma-slotd-demo-.service.d", "/etc/systemd/system/swarma.service.d",
			"/etc/systemd/system/slotd-demo.service.d", "/run/systemd/system.control/swarma-slotd-demox.service.d"} {
			dropIn(dir, overrideDropIn)(t)
		}
		plantSymlink(t, "/dev/null", "/etc/systemd/system/slotd-fixture-masked.service")
		f.invoke(t, f.checkArgs, "no files published", true)
		f.absent(t)
		f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
		f.requireInstalled(t)
		requireLoadedReviewed(t)
		uninstallPackage(t)
		f.absent(t)
	})

	// The post-reload readback is the effective-configuration witness for what
	// only exists after daemon-reload: a generator's output.
	t.Run("generated_dropin_refused_after_reload", func(t *testing.T) {
		f.absent(t)
		const generator = "/etc/systemd/system-generators/slotd-fixture-generator"
		plantFile(t, generator, []byte(`#!/bin/sh
set -eu
/usr/bin/mkdir -p "$1/swarma-slotd-demo.service.d"
printf '[Service]\nEnvironment=SLOTD_GENERATED_FIXTURE=1\n' > "$1/swarma-slotd-demo.service.d/50-slotd-fixture.conf"
`), 0755)
		f.invoke(t, f.checkArgs, "no files published", true)
		f.invoke(t, f.baseArgs, "slotd install refused: loaded daemon unit differs from the reviewed package; not started or enabled", false)
		props := loadedUnitProperties(t)
		if props["FragmentPath"] != installUnitPath || props["DropInPaths"] != "/run/systemd/generator/swarma-slotd-demo.service.d/50-slotd-fixture.conf" || props["ActiveState"] != "inactive" {
			t.Fatalf("systemd did not load the generated drop-in the readback refused: %q", props)
		}
		requireUnitDisabled(t)
		installed := f.requireInstalled(t)
		f.invoke(t, f.checkArgs, "slotd install refused: "+refused, false)
		requireUnchanged(t, installed, "refused rerun")
		if err := os.Remove(generator); err != nil {
			t.Fatal(err)
		}
		daemonReload(t)
		f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
		requireUnchanged(t, installed, "rerun without generator")
		requireLoadedReviewed(t)
		uninstallPackage(t)
		f.absent(t)
	})

	// A generator can equally add a dependency during the installer's own
	// daemon-reload. That changes no property the readback compares, so the
	// post-reload namespace scan is what refuses it.
	const foreign = "slotd-fixture-foreign.service"
	const afterReload = "additional or overridden daemon unit refused after reload; not started or enabled"
	dependencyGenerator := func(dir, entry, target string) string {
		return `/usr/bin/mkdir -p "$1/` + dir + `"
printf '[Unit]\nDescription=slotd fixture inert dependency\n\n[Service]\nType=oneshot\nExecStart=/bin/false\n' > "$1/` + foreign + `"
/usr/bin/ln -s "` + target + `" "$1/` + dir + `/` + entry + `"
`
	}
	type dependencyCase struct{ name, dir, entry, target, property, want string }
	forward := func(name, dir, property string) dependencyCase {
		return dependencyCase{name, dir, foreign, "$1/" + foreign, property, afterReload}
	}
	dependencyCases := []dependencyCase{
		forward("wants", installUnitName+".wants", "Wants"),
		forward("requires", installUnitName+".requires", "Requires"),
		forward("upholds", installUnitName+".upholds", "Upholds"),
		// Dash-prefix dependency directories apply to swarma-slotd-*.service only.
		forward("prefix_wants", "swarma-slotd-.service.wants", "Wants"),
		// A reverse link pulls the unit in. On the runner's systemd the loaded-unit
		// readback already refuses it (hosted run 43216606653), before the scan.
		{"reverse_wants", foreign + ".wants", installUnitName, installUnitPath, "WantedBy", "loaded daemon unit differs from the reviewed package; not started or enabled"},
	}
	t.Run("generated_dependency_refused_after_reload", func(t *testing.T) {
		for _, c := range dependencyCases {
			t.Run(c.name, func(t *testing.T) {
				f.absent(t)
				t.Cleanup(func() { uninstallPackage(t) })
				plantGenerator(t, dependencyGenerator(c.dir, c.entry, c.target))
				f.invoke(t, f.checkArgs, "no files published", true)
				f.invoke(t, f.baseArgs, "slotd install refused: "+c.want, false)
				// systemd itself loaded the generated dependency the installer refused.
				if deps := unitDependencies(t, c.property); !slices.Contains(deps, foreign) {
					t.Fatalf("systemd did not load the generated %s dependency: %q", c.property, deps)
				}
				props := loadedUnitProperties(t)
				t.Logf("systemd readback after the refused install: %q", props)
				if props["ActiveState"] != "inactive" || props["FragmentPath"] != installUnitPath {
					t.Fatalf("refused unit was started or replaced: %q", props)
				}
				installed := f.requireInstalled(t)
				f.invoke(t, f.checkArgs, "slotd install refused: "+refused, false)
				requireUnchanged(t, installed, "refused rerun")
				if err := os.Remove(fixtureGenerator); err != nil {
					t.Fatal(err)
				}
				daemonReload(t)
				f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
				requireUnchanged(t, installed, "rerun without generator")
				requireLoadedReviewed(t)
				if deps := unitDependencies(t, c.property); slices.Contains(deps, foreign) {
					t.Fatalf("generated %s dependency outlived its generator: %q", c.property, deps)
				}
				uninstallPackage(t)
				f.absent(t)
			})
		}
	})

	// Valid neighbour: a generator whose dependency directories systemd does
	// not merge into this unit runs at the installer's reload, and the install
	// succeeds with the reviewed unit and no added dependency.
	t.Run("unrelated_generated_dependencies_accepted", func(t *testing.T) {
		f.absent(t)
		t.Cleanup(func() { uninstallPackage(t) })
		plantGenerator(t, dependencyGenerator("swarma-slotd-demo-.service.wants", foreign, "$1/"+foreign)+
			`/usr/bin/mkdir -p "$1/swarma.service.requires"
/usr/bin/ln -s "$1/`+foreign+`" "$1/swarma.service.requires/`+foreign+`"
`)
		f.invoke(t, f.checkArgs, "no files published", true)
		f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
		for _, path := range []string{"/run/systemd/generator/swarma-slotd-demo-.service.wants/" + foreign, "/run/systemd/generator/swarma.service.requires/" + foreign} {
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("neighbour generator did not run at the installer's reload: %v", err)
			}
		}
		f.requireInstalled(t)
		requireLoadedReviewed(t)
		requireUnitDisabled(t)
		for _, property := range []string{"Wants", "Requires", "Upholds", "WantedBy"} {
			if deps := unitDependencies(t, property); slices.Contains(deps, foreign) {
				t.Fatalf("unrelated generator changed the unit's %s: %q", property, deps)
			}
		}
		if err := os.Remove(fixtureGenerator); err != nil {
			t.Fatal(err)
		}
		uninstallPackage(t)
		f.absent(t)
	})

	// Narrowing mutants of the post-reload scan (apply mode only). Each keeps
	// the loaded-unit readback, so a generated drop-in is still refused; the
	// named generated-dependency case is refused by the real installer above
	// and admitted by the mutant here, while systemd reports the dependency.
	const postReload = `unit_namespace(LOAD_PATHS + tuple(path for path in manager_unit_paths() if path not in LOAD_PATHS))`
	for _, m := range []struct {
		name, replacement string
		killer            dependencyCase
	}{
		// Re-checks unit files and .d drop-ins, but no dependency directory.
		{"postreload_dependency_dirs_omitted", `if any(n == UNIT_NAME or n in {s + ".d" for s in UNIT_SCOPES} for p in LOAD_PATHS + tuple(manager_unit_paths()) if os.path.isdir(p) for n in os.listdir(p) if os.path.join(p, n) != UNIT): raise Refusal("additional or overridden daemon unit refused")`,
			dependencyCases[0]},
		// Drops the dependency suffixes; the own-name catch-all still refuses
		// swarma-slotd-demo.service.wants, so the dash-prefix case kills it.
		{"postreload_dependency_suffixes_dropped", `globals()["DEPENDENCY_DIRS"] = (); ` + postReload, dependencyCases[3]},
	} {
		t.Run("mutant_"+m.name+"_killed_by_generated_dependency_refused_after_reload_"+m.killer.name, func(t *testing.T) {
			f.absent(t)
			t.Cleanup(func() { uninstallPackage(t) })
			mutant := f.mutantApplyArgs(t, m.name, postReload, m.replacement)
			plantGenerator(t, dependencyGenerator(m.killer.dir, m.killer.entry, m.killer.target))
			f.invoke(t, mutant, "daemon not started or enabled", true)
			if deps := unitDependencies(t, m.killer.property); !slices.Contains(deps, foreign) {
				t.Fatalf("mutant admission is vacuous; systemd has no generated %s dependency: %q", m.killer.property, deps)
			}
			f.requireInstalled(t)
			if err := os.Remove(fixtureGenerator); err != nil {
				t.Fatal(err)
			}
			uninstallPackage(t)
			f.absent(t)
		})
	}
}

// Proves an existing exact root:root 0755 config directory is inventoried
// before publication: any basename other than policy.json (a regular file,
// including a hidden one or a stale publication temporary, a directory, a
// symlink, dangling or to the identical policy) is refused in --check and
// apply mode, beside an absent or an identical policy. Extra entries are
// neither deleted nor adopted and every object stays unchanged. Valid
// neighbour: the identical root:root 0640 policy alone passes --check and a
// full install that keeps that policy inode. A mutant whose inventory skips
// symlinks admits the planted symlink.
func TestRootInstallConfigInventory(t *testing.T) {
	f := newInstallFixture(t)
	const refused = "unexpected entry in config directory refused"
	policy := f.expected[installPolicyPath]
	config := func(t *testing.T, identical bool) []string {
		plantDir(t, installConfigPath, 0755)
		if !identical {
			return []string{installConfigPath}
		}
		plantFile(t, installPolicyPath, policy.data, policy.mode)
		return []string{installConfigPath, installPolicyPath}
	}
	for _, identical := range []bool{false, true} {
		suffix := "_policy_absent"
		if identical {
			suffix = "_identical_policy"
		}
		for _, c := range []struct {
			name  string
			plant func(t *testing.T, path string)
		}{
			{"extra_file", func(t *testing.T, path string) { plantFile(t, path, []byte("foreign retained file\n"), 0644) }},
			{"extra_dir", func(t *testing.T, path string) { plantDir(t, path, 0755) }},
			{"extra_symlink_to_policy", func(t *testing.T, path string) { plantSymlink(t, installPolicyPath, path) }},
			{"extra_dangling_symlink", func(t *testing.T, path string) { plantSymlink(t, "/nonexistent/slotd-fixture", path) }},
		} {
			f.refuseBoth(t, c.name+suffix, refused, func(t *testing.T) []string {
				watched := config(t, identical)
				path := filepath.Join(installConfigPath, "unexpected.conf")
				c.plant(t, path)
				return append(watched, path)
			})
		}
	}
	for _, c := range []struct{ name, entry string }{
		{"hidden_swap_file", ".policy.json.swp"}, {"stale_publication_temporary", ".slotd-install-00112233445566778899aabbccddeeff"},
	} {
		f.refuseBoth(t, c.name, refused, func(t *testing.T) []string {
			watched := config(t, true)
			path := filepath.Join(installConfigPath, c.entry)
			plantFile(t, path, policy.data, policy.mode)
			return append(watched, path)
		})
	}

	t.Run("mutant_symlink_class_skipped_killed_by_extra_symlink_to_policy", func(t *testing.T) {
		f.absent(t)
		mutant := f.mutantCheckArgs(t, "symlink_class_skipped",
			`    if any(name != os.path.basename(POLICY) for name in os.listdir(fd)):`,
			`    if any(name != os.path.basename(POLICY) and not os.path.islink(os.path.join(os.path.dirname(POLICY), name)) for name in os.listdir(fd)):`)
		config(t, true)
		plantSymlink(t, installPolicyPath, filepath.Join(installConfigPath, "unexpected.conf"))
		f.invoke(t, f.checkArgs, "slotd install refused: "+refused, false)
		f.invoke(t, mutant, "no files published", true)
		f.absent(t, installConfigPath, installPolicyPath)
	})

	t.Run("identical_policy_accepted", func(t *testing.T) {
		f.absent(t)
		config(t, true)
		kept := snapshotObject(t, installPolicyPath)
		f.invoke(t, f.checkArgs, "no files published", true)
		f.absent(t, installConfigPath, installPolicyPath)
		f.invoke(t, f.baseArgs, "daemon not started or enabled", true)
		f.requireInstalled(t)
		requireUnchanged(t, map[string]objectSnapshot{installPolicyPath: kept}, "identical policy install")
		requireLoadedReviewed(t)
		for _, path := range []string{installUnitPath, installStopPath, fenceBinaryPath} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		daemonReload(t)
		f.absent(t, installConfigPath, installPolicyPath)
	})
}
