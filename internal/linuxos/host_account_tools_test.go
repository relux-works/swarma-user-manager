//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const hostAccountToolsOptIn = "SWARMA_TEST_HOST_ACCOUNT_TOOLS"
const hostAccountToolsSkip = "host account tools disabled; set SWARMA_TEST_HOST_ACCOUNT_TOOLS=1 only on a prepared disposable host"

// Check this before account lookups, temporary files or installed-tool probes.
func requireHostAccountTools(t *testing.T) {
	t.Helper()
	if err := hostAccountDeclaration(os.Getenv(hostAccountToolsOptIn), os.Getenv("SWARMA_TEST_DISPOSABLE_DECLARATION")); err != nil {
		t.Skip(hostAccountToolsSkip)
	}
}

// A declaration is an operator assertion about this exact boot, not a detector
// of an ephemeral VM. File ownership/mode and exact schema prevent accidental
// shell inheritance from being sufficient. This helper never changes host state.
type disposableHostDeclaration struct {
	Version     int    `json:"version"`
	Disposition string `json:"disposition"`
	Scope       string `json:"scope"`
	Host        string `json:"host"`
	BootID      string `json:"boot_id"`
}

func hostAccountDeclaration(value, path string) error {
	if value != "1" {
		return fmt.Errorf("exact opt-in required")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("absolute declaration required")
	}
	// No symlink components, no devices/FIFOs, bounded reads, current owner only.
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return fmt.Errorf("declaration must be an owned single-link 0600 regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return fmt.Errorf("invalid declaration size: %v", err)
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	// Compare canonical bytes as well as fields: duplicate keys, unknown fields,
	// trailing records and partial declarations are all refused.
	expected, err := json.Marshal(disposableHostDeclaration{1, "DISPOSABLE", "linuxos-test-accounts-only", host, strings.TrimSpace(string(boot))})
	if err != nil {
		return err
	}
	if !bytes.Equal(data, append(expected, '\n')) {
		return fmt.Errorf("host/boot-bound DISPOSABLE declaration required")
	}
	return nil
}

// The legacy probes use pre-existing accounts (including root in the parser
// vectors), and root qualification imports state from another invocation.
// Neither a prefix nor that state is evidence of creation in this run. Keep the
// original bodies/assertions for independent disposable-host redesign, but do
// not execute them without a live scoped creation receipt. No provisioner is
// supplied by this test-hygiene change.
func requirePreparedHostFixture(t *testing.T) {
	t.Helper()
	requireHostAccountTools(t)
	// No live provisioner/receipt is available to these legacy entrypoints.
	// In particular, do not infer ownership from platform-test-* or saved flags.
	var ledger *hostOwnershipLedger
	if err := ledger.operate(nil, false, func() error { return nil }); err != nil {
		t.Skip("prepared host body disabled: no same-run creation receipts; prior accounts/state cannot be adopted")
	}
}

// Never enable host operations here. Each non-enabling value must skip both
// entrypoints for this reason, before their other host-dependent checks.
func TestHostAccountToolsDefaultSkip(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		set         bool
	}{
		{"unset", "", false},
		{"empty", "", true},
		{"zero", "0", true},
		{"true", "true", true},
		{"space-one", " 1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, path, "-test.run=^(TestAccountToolNonRootParsing|TestPeerTemporaryFileInventory)$", "-test.count=1", "-test.v")
			cmd.Env = []string{}
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, hostAccountToolsOptIn+"=") && !strings.HasPrefix(entry, "SWARMA_TEST_UNPRIVILEGED=") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			if tc.set {
				cmd.Env = append(cmd.Env, hostAccountToolsOptIn+"="+tc.value)
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || err != nil {
				t.Fatalf("default host-tool entrypoints failed: %v (context: %v)\n%s", err, ctx.Err(), output)
			}
			for _, name := range []string{"TestAccountToolNonRootParsing", "TestPeerTemporaryFileInventory"} {
				if !strings.Contains(string(output), "--- SKIP: "+name+" ") {
					t.Fatalf("%s did not skip\n%s", name, output)
				}
			}
			if strings.Count(string(output), hostAccountToolsSkip) != 2 {
				t.Fatalf("entrypoints did not both skip at the opt-in gate\n%s", output)
			}
		})
	}
}
