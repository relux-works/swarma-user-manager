//go:build linux

package slotd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

//go:embed testdata/t19-realhost/unit-properties.json
var t19PropertyTemplate []byte

func t19ExpectedProperties(p policy, r durableRecord) (map[string]string, error) {
	id := r.Identity
	var v map[string]string
	if err := json.Unmarshal(t19PropertyTemplate, &v); err != nil {
		return nil, err
	}
	var binds, allow []string
	for _, b := range slotIdentityBinds(p, id, nil) {
		binds = append(binds, b+":"+strings.TrimPrefix(b, "-")+":rbind")
	}
	for _, a := range systemdAddressProperties(p)[1:] {
		allow = append(allow, strings.TrimPrefix(a, "IPAddressAllow="))
	}
	groups, _ := slotSupplementaryGroups(p, id)
	quota, err := cpuQuotaMicros(p.Caps.CPUQuota)
	if err != nil {
		return nil, err
	}
	replace := strings.NewReplacer("{{CPU_US}}", strconv.FormatInt(quota, 10), "{{RUNTIME_US}}", strconv.FormatInt(r.UnitRuntimeUS, 10), "{{UNIT_TOKEN}}", r.UnitToken, "{{UNIT}}", id.Unit, "{{USER}}", id.Name, "{{HOME}}", id.Home, "{{MEMORY}}", strconv.FormatUint(memoryBytes(p.Caps.MemoryMax), 10), "{{TASKS}}", strconv.FormatUint(uint64(p.Caps.TasksMax), 10), "{{BIND_RO}}", strings.Join(binds, " "), "{{IP_ALLOW}}", strings.Join(allow, " "), "{{GROUPS}}", groups)
	for k, val := range v {
		v[k] = replace.Replace(val)
	}
	return v, nil
}
func t19PropertyBytes(v map[string]string) []byte {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + v[k] + "\n")
	}
	return []byte(b.String())
}

// The projection is closed. The production verifier's set-valued rows use its
// own sameWords comparison (including duplicate counts); other values retain
// byte comparison, including BindPaths for the admitted v0 profile. The returned
// evidence preserves the actual rendered values.
// systemd omits empty EnvironmentFiles even with --all; a separate query below
// proves the typed empty D-Bus array, so absence can never stand for empty.
func t19CompareProperties(raw []byte, expected map[string]string) (map[string]string, error) {
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return got, errors.New("malformed property line")
		}
		if _, ok := expected[k]; !ok {
			return got, errors.New("extra property: " + k)
		}
		if _, ok := got[k]; ok {
			return got, errors.New("duplicate property: " + k)
		}
		got[k] = v
	}
	for k, want := range expected {
		v, ok := got[k]
		if !ok {
			return got, errors.New("missing property: " + k)
		}
		switch k {
		case "TemporaryFileSystem", "BindReadOnlyPaths", "RestrictAddressFamilies", "IPAddressDeny", "IPAddressAllow":
			if !sameWords(v, strings.Fields(want)) {
				return got, fmt.Errorf("property set mismatch: %s: got %q want %q", k, v, want)
			}
			continue
		}
		if v != want {
			return got, fmt.Errorf("property byte mismatch: %s: got %q want %q", k, v, want)
		}
	}
	return got, nil
}
func t19ReadStrictProperties(ctx context.Context, p policy, r durableRecord) (map[string]string, string, error) {
	expected, err := t19ExpectedProperties(p, r)
	if err != nil {
		return nil, "", err
	}
	var keys []string
	for k := range expected {
		if k != "EnvironmentFiles" && k != "CPUQuotaPerSecUSec" && k != "RuntimeMaxUSec" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	b, err := runFixedTool(ctx, toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-pager", "--all", "show", "--property=" + strings.Join(keys, ","), "--", r.Identity.Unit}})
	if err != nil {
		return nil, string(t19PropertyBytes(expected)), err
	}
	objectBytes, err := runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "--json=short", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", r.Identity.Unit}})
	if err != nil {
		return nil, string(t19PropertyBytes(expected)), err
	}
	object, err := parseUnitObjectJSON(objectBytes)
	if err != nil {
		return nil, string(t19PropertyBytes(expected)), err
	}
	env, err := runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "get-property", "org.freedesktop.systemd1", object, "org.freedesktop.systemd1.Service", "EnvironmentFiles"}})
	if err != nil {
		return nil, string(t19PropertyBytes(expected)), err
	}
	if err = t19EmptyEnvironmentFiles(env); err != nil {
		return nil, string(t19PropertyBytes(expected)), err
	}
	b = append(b, []byte("EnvironmentFiles=\n")...)
	for _, key := range []string{"CPUQuotaPerSecUSec", "RuntimeMaxUSec"} {
		raw, err := runFixedTool(ctx, toolInvocation{Path: busctlPath, Args: []string{"--system", "--no-pager", "get-property", "org.freedesktop.systemd1", object, "org.freedesktop.systemd1.Service", key}})
		if err != nil {
			return nil, string(t19PropertyBytes(expected)), err
		}
		if len(raw) == 0 || raw[len(raw)-1] != '\n' {
			return nil, string(t19PropertyBytes(expected)), errors.New("missing typed duration readback")
		}
		b = append(b, []byte(key+"="+string(raw))...)
	}
	got, err := t19CompareProperties(b, expected)
	return got, string(t19PropertyBytes(expected)), err
}

func t19EmptyEnvironmentFiles(b []byte) error {
	if !bytes.Equal(b, []byte("a(sb) 0\n")) {
		return errors.New("EnvironmentFiles is missing, malformed or nonempty")
	}
	return nil
}
