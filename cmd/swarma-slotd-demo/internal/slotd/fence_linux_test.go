//go:build linux

package slotd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Proves actual limit-file parsing rejects absent/unlimited/unequal values beside equivalent quota/period ratios; no kernel enforcement claim.
func TestFenceKernelLimitValues(t *testing.T) {
	p, _ := durableFixture(t)
	p.Caps = capsPolicy{CPUQuota: "100%", MemoryMax: "256M", TasksMax: 64}
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, tc := range []struct {
		cpu, memory, tasks string
		valid              bool
	}{
		{"100000 100000\n", "268435456\n", "64\n", true},
		{"200000 200000\n", "268435456\n", "64\n", true},
		{"max 100000\n", "268435456\n", "64\n", false},
		{"200000 100000\n", "268435456\n", "64\n", false},
		{"100000 100000\n", "max\n", "64\n", false},
		{"100000 100000\n", "268435457\n", "64\n", false},
		{"100000 100000\n", "268435456\n", "max\n", false},
		{"100000 100000\n", "268435456\n", "65\n", false},
		{"100000 0\n", "268435456\n", "64\n", false},
	} {
		for name, value := range map[string]string{"cpu.max": tc.cpu, "memory.max": tc.memory, "pids.max": tc.tasks} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
		err := verifyKernelLimits(f, p)
		if tc.valid && err != nil {
			t.Fatal(err)
		}
		if !tc.valid && !errors.Is(err, errFenceLimits) {
			t.Fatalf("wrong refusal: %v", err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "cpu.max")); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(verifyKernelLimits(f, p), errFenceLimits) {
		t.Fatal("missing controller admitted")
	}
}

// Proves the closed reference has deny-any/allow-precedence/exit and direction-specific address offsets; hosted tests separately compare real kernel programs.
func TestFenceReferenceInstructions(t *testing.T) {
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, firewallInstructions(-1, -1, false)); err != nil {
		t.Fatal(err)
	}
	want := []byte{0xbf, 0x16, 0, 0, 0, 0, 0, 0, 0x61, 0x67, 16, 0, 0, 0, 0, 0, 0xb4, 8, 0, 0, 0, 0, 0, 0, 0x44, 8, 0, 0, 2, 0, 0, 0, 0xb7, 0, 0, 0, 1, 0, 0, 0, 0x55, 8, 1, 0, 2, 0, 0, 0, 0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(raw.Bytes(), want) {
		t.Fatal("deny-any reference changed")
	}
	in, out := firewallInstructions(10, 11, true), firewallInstructions(10, 11, false)
	if len(in) != 38 || len(out) != 38 || in[5].Imm != 12 || out[5].Imm != 16 || in[20].Imm != 8 || out[20].Imm != 24 {
		t.Fatal("address offsets changed")
	}
	if in[10].Imm != 10 || in[25].Imm != 11 {
		t.Fatal("map bindings changed")
	}
}

// Proves unsupported, unknown, absent and wrong-program outcomes remain distinct private codes; none creates a new wire error.
func TestFenceRefusalCodes(t *testing.T) {
	for _, tc := range []struct{ err, want error }{{unix.EOPNOTSUPP, errFenceBPFUnsupported}, {unix.ENOSYS, errFenceBPFUnsupported}, {unix.EPERM, errFenceBPFUnknown}, {unix.EIO, errFenceBPFUnknown}, {errFenceBPFMissing, errFenceBPFMissing}, {errFenceBPFPolicy, errFenceBPFPolicy}} {
		if got := classifyBPFError(tc.err); !errors.Is(got, tc.want) {
			t.Fatalf("wrong classification: %v", got)
		}
	}
	if EnforcementFence(nil) != 80 || EnforcementFence([]string{"17"}) != 80 {
		t.Fatal("invalid invocation admitted")
	}
}
