//go:build linux

package linuxos

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strings"
	"testing"
)

// capget matches the same kernel thread's proc CapEff, including the fixed-width
// zero representation. This does not qualify a root deployment's bounding set.
func TestD1KernelEffectiveCapabilities(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	got, e := EffectiveCapabilities()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile("/proc/thread-self/status")
	if e != nil {
		t.Fatal(e)
	}
	want := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			want = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	if len(got) != 16 || want == "" || got != want {
		t.Fatalf("kernel capability mismatch: got %q want %q", got, want)
	}
}

// Different actual thread masks or an unreadable/exited thread cannot produce
// a uniform issuer mask; equal reduced masks are the bounded positive control.
func TestD1CapabilityThreadAgreement(t *testing.T) {
	for _, mode := range []string{"valid", "different", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			applied := false
			got, e := consistentEffectiveCapabilities([]int32{0, 123}, func(tid int32) (uint64, error) {
				if tid == 123 {
					applied = true
					if mode == "different" {
						return 1 << 12, nil
					}
					if mode == "unreadable" {
						return 0, unix.ESRCH
					}
				}
				return 0, nil
			})
			if !applied {
				t.Fatal("thread control not applied")
			}
			if mode == "valid" {
				if e != nil || got != "0000000000000000" {
					t.Fatal("valid control", got, e)
				}
			} else if e == nil || got != "" {
				t.Fatal("mixed/unreadable threads accepted", got, e)
			}
			if mode == "unreadable" && !errors.Is(e, unix.ESRCH) {
				t.Fatal("wrong thread refusal", e)
			}
		})
	}
}
