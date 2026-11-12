package slotd

import (
	"slices"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

// Proves the typed vector contains the codec's exact argv and exactly the home
// plus journal writable binds. Missing/drifted bindings yield no vector.
func TestStationStartInvocation(t *testing.T) {
	p, r := stationRecordFixture(t)
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	now := r.Binding.NotAfter.Add(-2 * time.Minute)
	inv, err := startInvocation(p, r.Slot, r.Binding, now, m)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(inv.Args, "--")
	if i < 0 || len(inv.Args) < i+3 || inv.Args[i+1] != slotLauncherPath || inv.Args[i+2] != slotLaunchFlag || payloadlaunch.ValidateArgv(m, inv.Args[i+3:]) != nil {
		t.Fatal("typed argv drift")
	}
	paths, err := payloadlaunch.PathsFor(m.UID)
	if err != nil {
		t.Fatal(err)
	}
	wantRO := "--property=BindReadOnlyPaths=" + quoteSystemdWord("-"+walletSocketDir) + " " + quoteSystemdWord(p.Payload.StationProfile.Executable) + " " + quoteSystemdWord(paths.Inputs) + " " + quoteSystemdWord(paths.Envelope+"/static")
	if !slices.Contains(inv.Args[:i], wantRO) {
		t.Fatal("station read-only binds", inv.Args[:i])
	}
	want := "--property=BindPaths=" + quoteSystemdWord(r.Identity.Home) + " " + quoteSystemdWord(m.Journal.Path)
	binds := 0
	for _, a := range inv.Args[:i] {
		if len(a) >= len("--property=BindPaths=") && a[:len("--property=BindPaths=")] == "--property=BindPaths=" {
			binds++
			if a != want {
				t.Fatal("unexpected writable bind", a)
			}
		}
	}
	if binds != 1 {
		t.Fatal("bind property count", binds)
	}
	for _, a := range []string{"--property=SupplementaryGroups=", "--property=Environment=", "--property=EnvironmentFile=", "--property=PassEnvironment="} {
		if !slices.Contains(inv.Args[:i], a) {
			t.Fatal("missing reset", a)
		}
	}
	for name, change := range map[string]func(*payloadlaunch.Manifest){"other slot": func(m *payloadlaunch.Manifest) { m.Slot++ }, "other uid": func(m *payloadlaunch.Manifest) { m.UID++; m.GID++ }, "obsolete profile": func(m *payloadlaunch.Manifest) { m.Profile.Model = "other" }, "other bootstrap": func(m *payloadlaunch.Manifest) { m.Bootstrap.SHA256 = m.CA.SHA256 }} {
		t.Run(name, func(t *testing.T) {
			bad := m
			change(&bad)
			got, err := startInvocation(p, r.Slot, r.Binding, now, bad)
			if err == nil || got.Path != "" || got.Args != nil {
				t.Fatal("drift produced vector", err)
			}
		})
	}
	if got, err := startInvocation(p, r.Slot, r.Binding, now); err == nil || got.Path != "" {
		t.Fatal("missing manifest admitted")
	}
}

// The model value at argv[18] remains literal even when it begins with a dash;
// replacing it with a normalized option form violates the codec's exact vector.
func TestStationLiteralModelArgv(t *testing.T) {
	p, r := stationRecordFixture(t)
	m, err := stationManifest(&r)
	if err != nil {
		t.Fatal(err)
	}
	p.Payload.StationProfile.Model = "-ca"
	m.Profile.Model = "-ca"
	inv, err := startInvocation(p, r.Slot, r.Binding, r.Binding.NotAfter.Add(-2*time.Minute), m)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(inv.Args, "--")
	if i < 0 {
		t.Fatal("missing executable boundary")
	}
	argv := inv.Args[i+3:]
	if len(argv) != 21 || argv[18] != "-ca" || payloadlaunch.ValidateArgv(m, argv) != nil {
		t.Fatal("literal model changed")
	}
	changed := append([]string{}, argv...)
	changed[18] = "--model=-ca"
	if err := payloadlaunch.ValidateArgv(m, changed); err != payloadlaunch.ErrBinding {
		t.Fatal("wrong normalized-vector refusal", err)
	}
}
