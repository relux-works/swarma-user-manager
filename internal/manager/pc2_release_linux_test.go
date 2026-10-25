//go:build linux

package manager

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Claim: the mechanical direct consumer syncs an exact released closure and
// returns a diagnostic for the same obligation, with no append/credit capability.
func TestManagerRecoveryDirectConsumption(t *testing.T) {
	f := newRecoveryFixture(t, "durable")
	f.run(t)
	c := f.releaseContext(t)
	p, e := prepareRecoveryRelease(&c)
	if e != nil {
		t.Fatal(e)
	}
	before := censusTreeBytes(t, f.root)
	r, e := consumeRecoveryRelease(context.Background(), p)
	if e != nil || r.ID != c.closure.accepted.id || r.Hold != c.closure.accepted.hold {
		t.Fatal(r, e)
	}
	if _, e := consumeRecoveryRelease(context.Background(), p); !errors.Is(e, ErrRecoveryUnavailable) {
		t.Fatal("repeated consumption", e)
	}
	censusSameTree(t, before, censusTreeBytes(t, f.root))
}

// Claim: accepted current metadata passes; changes after preparation (including
// equal-byte inode substitution and coherent old local bytes) deny observations.
func TestManagerRecoveryCurrency(t *testing.T) {
	for _, name := range []string{"control", "root", "guard", "floor", "intent", "same-bytes-inode", "coherent-restore", "cancelled", "marker-returned", "participant-identity"} {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t, "durable")
			f.run(t)
			c := f.releaseContext(t)
			p, e := prepareRecoveryRelease(&c)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			switch name {
			case "root":
				b, e := os.ReadFile(filepath.Join(f.root, "auth/root.json"))
				if e != nil {
					t.Fatal(e)
				}
				changed := bytes.ReplaceAll(b, []byte(`"revision":1`), []byte(`"revision":2`))
				if bytes.Equal(b, changed) || len(b) != len(changed) {
					t.Fatal("equal-length valid root control not applied")
				}
				censusWrite(t, filepath.Join(f.root, "auth/root.json"), changed, 0640)
			case "guard", "floor", "intent":
				censusWrite(t, filepath.Join(f.root, "auth", name+".json"), []byte(`{"changed":true}`), 0640)
			case "same-bytes-inode":
				b, e := os.ReadFile(filepath.Join(f.root, "auth/root.json"))
				if e != nil {
					t.Fatal(e)
				}
				censusWrite(t, filepath.Join(f.root, "auth/new-root"), b, 0640)
				if e = os.Rename(filepath.Join(f.root, "auth/new-root"), filepath.Join(f.root, "auth/root.json")); e != nil {
					t.Fatal(e)
				}
			case "coherent-restore":
				for _, name := range []string{"root", "floor", "intent"} {
					censusWrite(t, filepath.Join(f.root, "auth", name+".json"), []byte(`{"fixture":"old-coherent-set"}`), 0640)
				}
			case "cancelled":
				cc, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cc
			case "marker-returned":
				censusWrite(t, filepath.Join(f.root, "generations/writer.pending"), []byte("later unresolved marker"), 0644)
			case "participant-identity":
				censusWrite(t, filepath.Join(f.root, "auth/new-participant"), []byte(`{}`), 0640)
				if e = os.Rename(filepath.Join(f.root, "auth/new-participant"), filepath.Join(f.root, "auth/participant-payload.json")); e != nil {
					t.Fatal(e)
				}
			}
			r, e := consumeRecoveryRelease(ctx, p)
			if name == "control" {
				if e != nil || r.ID == "" {
					t.Fatal("valid control", r, e)
				}
			} else if !errors.Is(e, ErrRecoveryUnavailable) || r.ID != "" {
				t.Fatal("stale result accepted", r, e)
			}
		})
	}
}

// Claim: exactly the original final roles/counts and tighter per-file bounds are
// required; spare defensive ceilings never authorize an extra metadata schema.
func TestManagerRecoveryFinalReadSet(t *testing.T) {
	f := newRecoveryFixture(t, "durable")
	f.run(t)
	c := f.releaseContext(t)
	if _, e := prepareRecoveryRelease(&c); e != nil {
		t.Fatal("valid control", e)
	}
	c.metadata = append(c.metadata, c.metadata[0])
	if _, e := prepareRecoveryRelease(&c); !errors.Is(e, ErrRecoveryUnavailable) {
		t.Fatal("extra read accepted", e)
	}
	c.metadata = c.metadata[:12]
	c.participants = c.participants[:9]
	if _, e := prepareRecoveryRelease(&c); !errors.Is(e, ErrRecoveryUnavailable) {
		t.Fatal("missing role accepted", e)
	}
}

// Claim: genuine authority recovery uses its authority-TX origin and null
// attempt union, retaining the same charged hold through direct consumption.
func TestManagerRecoveryAuthorityLifecycle(t *testing.T) {
	f := newRecoveryFixtureKind(t, "durable", "authority")
	f.run(t)
	c := f.releaseContext(t)
	if c.metadata[6].file != nil {
		t.Fatal("authority fabricated A2")
	}
	p, e := prepareRecoveryRelease(&c)
	if e != nil {
		t.Fatal(e)
	}
	r, e := consumeRecoveryRelease(context.Background(), p)
	if e != nil || r.Hold != f.c.closure.accepted.hold {
		t.Fatal(r, e)
	}
}
