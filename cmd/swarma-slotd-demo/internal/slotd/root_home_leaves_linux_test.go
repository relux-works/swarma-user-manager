//go:build linux

package slotd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Proves real non-root payload symlink/socket/FIFO/hardlink and safe home-mode changes retire by no-follow leaf unlink; a foreign leaf first refuses before any lifecycle resource deletion.
func TestRootPayloadLeaves(t *testing.T) {
	p, r, dir := rootFixture(t)
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(r.Identity.Home, "leaves-ready")
	setProbePolicy(t, &p, dir, probeSpec{Report: report, Hold: true, LeafTarget: target})
	engine, _, effects := realEngine(t, p, &r, dir)
	created, code := engine.apply(context.Background(), currentCreate(t, &r))
	if code != "" {
		if created != nil {
			r = *created
		}
		t.Fatal(code)
	}
	r = *created
	started, code := engine.apply(context.Background(), request{Op: "start", Slot: r.Slot})
	if started != nil {
		r = *started
	}
	if code != "" {
		t.Fatal(code)
	}
	awaitProbe(t, report, 0)
	// Deletion's mode tolerance must not admit a new start with a changed home.
	if f, err := effects.homes.openOwned(&r); err == nil {
		f.Close()
		t.Fatal("start-path ownership check admitted changed home mode")
	}
	for _, name := range []string{"symlink", "socket", "fifo", "hardlink", "writable"} {
		st, err := os.Lstat(filepath.Join(r.Identity.Home, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "symlink" && st.Mode()&os.ModeSymlink == 0 {
			t.Fatal("symlink plant missing")
		}
		if name == "socket" && st.Mode()&os.ModeSocket == 0 {
			t.Fatal("socket plant missing")
		}
		if name == "fifo" && st.Mode()&os.ModeNamedPipe == 0 {
			t.Fatal("FIFO plant missing")
		}
	}
	stopped, code := engine.apply(context.Background(), request{Op: "stop", Slot: r.Slot})
	if stopped != nil {
		r = *stopped
	}
	if code != "" {
		t.Fatal(code)
	}
	foreign := filepath.Join(r.Identity.Home, "foreign")
	if err := os.Symlink(target, foreign); err != nil {
		t.Fatal(err)
	}
	refused, code := engine.apply(context.Background(), request{Op: "destroy", Slot: r.Slot})
	if refused != nil {
		r = *refused
	}
	if code != internalError || r.Binding.State != failed {
		t.Fatal("foreign leaf did not refuse")
	}
	if err := verifyNFT(context.Background(), p, &r); err != nil {
		t.Fatal("foreign refusal removed NFT")
	}
	observed, err := observeAccounts(context.Background(), r.Identity)
	if err != nil || observed.matches(r.Accounts) != nil {
		t.Fatal("foreign refusal changed accounts")
	}
	for _, name := range []string{"bootstrap", "symlink", "socket", "fifo", "hardlink", "writable", "foreign"} {
		if _, err := os.Lstat(filepath.Join(r.Identity.Home, name)); err != nil {
			t.Fatal("foreign refusal removed neighbor")
		}
	}
	// Remove only the fixture's deliberately foreign leaf, then explicit failed
	// destroy must retire the real payload's ordinary contents without adoption.
	if err = os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	finalRecord, code := engine.apply(context.Background(), request{Op: "destroy", Slot: r.Slot})
	if finalRecord != nil {
		r = *finalRecord
	}
	if code != "" || r.Binding.State != destroyed {
		t.Fatalf("ordinary leaves blocked destroy: %s", code)
	}
	if _, err = os.Lstat(r.Identity.Home); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("home remains")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "untouched" {
		t.Fatal("leaf unlink followed symlink")
	}
}
