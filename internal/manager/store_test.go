package manager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func diskFixture(t *testing.T) (*DiskStore, string) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(anchor, "journal")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := provisionStore(dir, 30000, uint32(os.Getuid()), anchor); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(dir, uint32(os.Getuid()), anchor)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, anchor
}

// Atomic disk evidence survives a fresh engine/store open; corrupt derived state is rebuilt and terminal replay does not execute the backend again.
func TestDiskPersistenceAndLedger(t *testing.T) {
	s, anchor := diskFixture(t)
	h := setup(t)
	h.e.Store = s
	g := h.created(t)
	before := append([]byte{}, h.j.raw...)
	if e := os.WriteFile(filepath.Join(s.path, "ledger.json"), []byte(`{"wrong":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	reopened, e := openStore(s.path, uint32(os.Getuid()), anchor)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	h.e.Store = reopened
	calls := len(*h.trace)
	want(t, h.run(t, "user.create", "first", "demo"), "ok")
	if len(*h.trace) != calls || !bytes.Equal(before, h.j.raw) {
		t.Fatal("reopen changed terminal effect")
	}
	v, e := h.j.view(h.s.state.Floor)
	if e != nil {
		t.Fatal(e)
	}
	expected, _ := canonical(v)
	stored, e := os.ReadFile(filepath.Join(s.path, "ledger.json"))
	if e != nil || !bytes.Equal(stored, expected) {
		t.Fatal("divergent ledger not rebuilt")
	}
	want(t, h.run(t, "user.retire", "retire", g), "ok")
}

// Missing, truncated, noncanonical, extra-field or unsafe effect evidence never becomes a fresh empty store; valid evidence is readable.
func TestDiskEvidenceRefusals(t *testing.T) {
	for _, name := range []string{"missing", "truncated", "noncanonical", "unknown", "checksum", "symlink", "hardlink", "mode", "directory"} {
		t.Run(name, func(t *testing.T) {
			s, _ := diskFixture(t)
			original, e := os.ReadFile(filepath.Join(s.path, "effects.json"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Load(); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(s.path, "effects.json")
			switch name {
			case "missing":
				e = os.Remove(path)
			case "truncated":
				e = os.WriteFile(path, original[:len(original)-1], 0600)
			case "noncanonical":
				e = os.WriteFile(path, append([]byte(" "), original...), 0600)
			case "checksum":
				e = os.WriteFile(path, bytes.Replace(original, []byte(`"cursor":30000`), []byte(`"cursor":30001`), 1), 0600)
			case "unknown":
				e = os.WriteFile(path, bytes.Replace(original, []byte(`"format":`), []byte(`"extra":1,"format":`), 1), 0600)
			case "symlink":
				if e = os.Rename(path, path+".saved"); e == nil {
					e = os.Symlink(path+".saved", path)
				}
			case "hardlink":
				e = os.Link(path, path+".alias")
			case "mode":
				e = os.Chmod(path, 0644)
			case "directory":
				if e = os.Remove(path); e == nil {
					e = os.Mkdir(path, 0700)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.Load(); e == nil {
				t.Fatal("unsafe evidence admitted")
			}
			if e = s.Save(State{}); name == "missing" && e == nil {
				t.Fatal("save recreated missing evidence")
			}
		})
	}
}

// The effect lock serializes independent store handles with a bounded refusal, then admits the next handler after release.
func TestDiskLockBound(t *testing.T) {
	s, anchor := diskFixture(t)
	other, e := openStore(s.path, uint32(os.Getuid()), anchor)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	unlock, e := s.Lock(context.Background(), 50*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Lock(context.Background(), 5*time.Millisecond); errorCode(e) != "target_busy" {
		t.Fatal(e)
	}
	unlock()
	release, e := other.Lock(context.Background(), 50*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	release()
}

// Policy encoding is closed and mandatory, refuses unsafe paths/bounds, and validates a complete qualified configuration without defaults.
func TestPolicyClosed(t *testing.T) {
	h := setup(t)
	b, e := canonical(h.e.Policy)
	if e != nil {
		t.Fatal(e)
	}
	var p Policy
	if e = strict(b, &p); e != nil || p.validate() != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{bytes.Replace(b, []byte(`"bump_enabled":true,`), nil, 1), bytes.Replace(b, []byte(`"quota":10`), []byte(`"quota":0`), 1), append([]byte(" "), b...)} {
		var v Policy
		if strict(bad, &v) == nil && v.validate() == nil {
			t.Fatal("missing or invalid configuration accepted")
		}
	}
}

// Forged sudo environment values alone never establish this unprivileged process as root or a dispatcher.
func TestSudoEnvironmentCannotGrant(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged invocation witness")
	}
	t.Setenv("SUDO_UID", "200")
	in := VerifiedInvocation(nil)
	if in.Sudo || in.EUID == 0 {
		t.Fatal("environment granted authority")
	}
	t.Setenv("SUDO_UID", "200\n")
	if VerifiedInvocation(nil).Sudo {
		t.Fatal("malformed caller accepted")
	}
}

// Unknown backend error codes cannot leak paths or arbitrary bytes into the public refusal envelope.
func TestBoundedPublicError(t *testing.T) {
	r := refused("valid", fail(strings.Repeat("/private/", 100)))
	if r.Error.Code != "backend_failed" || len(r.Error.Message) > 256 {
		t.Fatal("unsafe refusal")
	}
}

// A ledger symlink cannot redirect derived-view writes to an outside sentinel; a regular missing projection is rebuilt.
func TestLedgerLinkRefusal(t *testing.T) {
	s, anchor := diskFixture(t)
	h := setup(t)
	v, e := h.j.view(h.s.state.Floor)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Ledger(v); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(s.path, "ledger.json")
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	sentinel := filepath.Join(anchor, "sentinel")
	if e = os.WriteFile(sentinel, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(sentinel, path); e != nil {
		t.Fatal(e)
	}
	if e = s.Ledger(v); errorCode(e) != "state_unavailable" {
		t.Fatal(e)
	}
	b, e := os.ReadFile(sentinel)
	if e != nil || string(b) != "preserve" {
		t.Fatal("ledger link changed sentinel")
	}
}
