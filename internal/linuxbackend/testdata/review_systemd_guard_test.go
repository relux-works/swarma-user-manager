package linuxos_test

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/linuxbackend"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The guard fingerprint must invalidate persistent changes to the qualified
// four-root/service namespace after a successful full capture, without provider
// RPC. The same changed fixtures must be rejected by the full public runtime.
// Only owned fixtures and sockets are touched; production methods are unchanged.
func TestReviewSystemdGuardNamespaceDrift(t *testing.T) {
	for _, mode := range []string{"control", "etc-dropin", "run-dropin", "run-host-dropin", "usr-lib-dropin", "endpoint-removal", "endpoint-replacement", "unexpected-service"} {
		t.Run(mode, func(t *testing.T) {
			runtime, l, path, calls := linuxos.QualificationSystemdFixture(t, "valid")
			adapter := linuxbackend.QualificationSystemdAdapter(runtime, []byte("reviewed deployment fixture"))
			names := []string{"files", "systemd"}
			before, e := linuxbackend.QualificationSystemdLocal(adapter, l)
			if e != nil {
				t.Fatal("local baseline", e)
			}
			if m, e := adapter.CaptureModules(context.Background(), names, l); e != nil || len(m) != 2 {
				t.Fatal("full positive capture", e)
			}
			root := filepath.Dir(filepath.Dir(path))
			socket := filepath.Join(root, "run/systemd/userdb/io.systemd.DynamicUser")
			switch mode {
			case "etc-dropin", "run-dropin", "run-host-dropin", "usr-lib-dropin":
				rel := map[string]string{"etc-dropin": "etc/userdb", "run-dropin": "run/userdb", "run-host-dropin": "run/host/userdb", "usr-lib-dropin": "usr/lib/userdb"}[mode]
				dir := filepath.Join(root, rel)
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(dir, ".unexpected-membership"), []byte("fixture"), 0600); e != nil {
					t.Fatal(e)
				}
			case "endpoint-removal", "endpoint-replacement":
				if e := os.Rename(socket, filepath.Join(root, "displaced-socket")); e != nil {
					t.Fatal(e)
				}
				if mode == "endpoint-replacement" {
					d, e := os.Open(filepath.Dir(socket))
					if e != nil {
						t.Fatal(e)
					}
					defer d.Close()
					listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: "/proc/self/fd/" + strconv.Itoa(int(d.Fd())) + "/io.systemd.DynamicUser", Net: "unix"})
					if e != nil {
						t.Fatal(e)
					}
					listener.SetUnlinkOnClose(false)
					t.Cleanup(func() { listener.Close() })
				}
			case "unexpected-service":
				if e := os.WriteFile(filepath.Join(filepath.Dir(socket), "io.review.Unknown"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			}
			count := calls()
			after, localErr := linuxbackend.QualificationSystemdLocal(adapter, l)
			if calls() != count {
				t.Fatal("local guard issued provider RPC")
			}
			modules, fullErr := adapter.CaptureModules(context.Background(), names, l)
			if mode == "control" {
				if localErr != nil || after != before || fullErr != nil || len(modules) != 2 {
					t.Fatal("unchanged control refused", localErr, fullErr)
				}
				return
			}
			var typed *linuxos.Error
			if !errors.As(fullErr, &typed) || typed.Code != "directory_unknown" || modules != nil {
				t.Fatal("mutation did not reach expected full-runtime refusal", fullErr, modules)
			}
			ops := []string{}
			var visit func(error)
			visit = func(cause error) {
				if cause == nil {
					return
				}
				if x, ok := cause.(*linuxos.Error); ok {
					ops = append(ops, x.Operation)
				}
				if multi, ok := cause.(interface{ Unwrap() []error }); ok {
					for _, part := range multi.Unwrap() {
						visit(part)
					}
				} else {
					visit(errors.Unwrap(cause))
				}
			}
			visit(fullErr)
			joined := strings.Join(ops, " -> ")
			expected := "userdb_services"
			if strings.HasSuffix(mode, "dropin") {
				expected = "userdb_dropin_present"
			}
			if mode == "endpoint-replacement" {
				expected = "userdb_closure"
			}
			if !strings.Contains(joined, expected) {
				t.Fatalf("unrelated full-runtime refusal: want=%s chain=%s", expected, joined)
			}
			if localErr == nil && after == before {
				t.Fatalf("local guard retained same fingerprint after %s; full capture refusal chain: %s", mode, joined)
			}
		})
	}
}
