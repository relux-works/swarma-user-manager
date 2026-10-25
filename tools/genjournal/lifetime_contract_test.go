package genjournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Frozen bindings reject independent scope/line/baseline substitutions. The
// exact binding passes; fixture validation is not manager authentication.
func TestAppendPreparedLifetimeBinding(t *testing.T) {
	mutations := map[string]func(*AppendBinding){
		"effect":      func(b *AppendBinding) { b.Request.Scope.EffectDigest = "foreign" },
		"owner":       func(b *AppendBinding) { b.Request.Scope.Owner = "foreign" },
		"provision":   func(b *AppendBinding) { b.Request.Scope.ProvisionEffect = "foreign" },
		"ordinal":     func(b *AppendBinding) { b.Request.Scope.Ordinal++ },
		"target":      func(b *AppendBinding) { b.Request.Scope.Target.RegistrationNumber++ },
		"epoch":       func(b *AppendBinding) { b.Request.Scope.Target.MasterEpoch++ },
		"generation":  func(b *AppendBinding) { b.Request.Scope.Target.Generation = lifetimePrevious },
		"source":      func(b *AppendBinding) { b.Request.Scope.Source = "foreign" },
		"reservation": func(b *AppendBinding) { b.Request.Scope.Reservation = "foreign" },
		"effects":     func(b *AppendBinding) { b.Request.Scope.EffectsLease = "" },
		"line":        func(b *AppendBinding) { b.Line = "changed\n" },
		"hash":        func(b *AppendBinding) { b.LineHash = ZeroHash },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.issuer.preparer = &lifetimeFixturePreparer{ops: f.ops, alter: func(b AppendBinding) AppendBinding { mutate(&b); return b }}
			_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
			wantCode(t, e, "bump_key_admission_unconfirmed")
			f.unchanged()
			f.noMarker()
		})
	}
	for _, name := range []string{"root", "guard", "inventory", "floor", "pin", "incarnation", "observation", "service", "counter"} {
		t.Run(name, func(t *testing.T) {
			f := newLifetimeFixture(t)
			b := &f.ops.binding.Baseline
			switch name {
			case "root":
				b.Root = ""
			case "guard":
				b.Guard = ""
			case "inventory":
				b.Inventory = ""
			case "floor":
				b.IndependentFloor = ""
			case "pin":
				b.Pin = ""
			case "incarnation":
				b.Incarnation = ""
			case "observation":
				b.Observation = ""
			case "service":
				b.ServiceInstance = ""
			case "counter":
				b.Counter = -1
			}
			_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
			wantCode(t, e, "bump_key_admission_unconfirmed")
			f.unchanged()
			f.noMarker()
		})
	}
	t.Run("authority-recheck", func(t *testing.T) {
		f := newLifetimeFixture(t)
		f.ops.check = func(*GuardWindow) error { return lifetimeDenied() }
		r, e := f.run()
		wantCode(t, e, "bump_key_admission_unconfirmed")
		if r.Outcome() != NoWrite || f.ops.consumes != 0 {
			t.Fatal("authority refusal wrote/consumed")
		}
		f.unchanged()
		f.locksFree()
	})
	t.Run("frozen-valid", func(t *testing.T) {
		f := newLifetimeFixture(t)
		p, g := f.prepare()
		f.ops.binding.Fence.PackageFences[0] = f.ops.binding.Fence.FileIdentity
		f.ops.binding.Append.Line = "changed"
		r, e := AppendPreparedLifetime(context.Background(), p, g)
		f.clean(r, e)
	})
}

// Recovery ancestry cannot authorize a prepared append, and changes after marker
// publication, including inode/transition/predecessor changes, never consume.
func TestAppendPreparedLifetimeExactTail(t *testing.T) {
	for _, mode := range []string{"ancestor", "advance", "journal-inode", "predecessor", "transition", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifetimeFixture(t)
			if mode == "ancestor" {
				f.request.Tail = genesis
				_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
				wantCode(t, e, "journal_stale_preparation")
				f.noMarker()
				return
			}
			if mode == "predecessor" {
				f.request.Scope.Target.PredecessorGeneration = strings.Repeat("3", 32)
				_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
				wantCode(t, e, "bump_key_admission_unconfirmed")
				f.noMarker()
				return
			}
			if mode == "transition" {
				if e := os.WriteFile(filepath.Join(f.path, "journal"), vector(t, "active"), 0644); e != nil {
					t.Fatal(e)
				}
				v, e := Verify(bytes.NewReader(vector(t, "active")), genesis)
				wantCode(t, e, "ok")
				f.request.Tail = v.Tail
				_, _, e = f.issuer.PrepareAppend(context.Background(), f.request)
				wantCode(t, e, "bump_key_admission_unconfirmed")
				f.noMarker()
				return
			}
			p, g := f.prepare()
			if mode == "journal-inode" {
				path := filepath.Join(f.path, "journal")
				if e := os.Rename(path, path+".old"); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(path, f.before, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "advance" {
				f.hooks.at = func(event string) error {
					if event == "after:marker-parent-sync" {
						line, e := Encode(Record{f.request.Tail.Seq + 1, f.request.Tail.Hash, 30002, strings.Repeat("3", 32), "creating", "user-manager", lifetimeStamp})
						if e != nil {
							return e
						}
						j, e := os.OpenFile(filepath.Join(f.path, "journal"), os.O_APPEND|os.O_WRONLY, 0)
						if e != nil {
							return e
						}
						_, e = j.Write(line)
						ce := j.Close()
						if e != nil {
							return e
						}
						return ce
					}
					return nil
				}
			}
			r, e := AppendPreparedLifetime(context.Background(), p, g)
			if mode == "valid" {
				f.clean(r, e)
				return
			}
			expected := "journal_stale_preparation"
			if mode == "journal-inode" {
				expected = "journal_path_type"
			}
			wantCode(t, e, expected)
			if r.Outcome() != NoWrite || f.ops.consumes != 0 {
				t.Fatal("journal refusal consumed")
			}
			f.locksFree()
		})
	}
}

// Entry/funding/cancellation/preflight refusals create no new incident; an
// unrelated existing marker remains unchanged. Funded valid input completes.
func TestAppendPreparedLifetimePreMarker(t *testing.T) {
	for _, mode := range []string{"reservation", "cancelled", "existing", "capacity", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifetimeFixture(t)
			if mode == "reservation" {
				f.request.Scope.Reservation = ""
				_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
				wantCode(t, e, "bump_key_admission_unconfirmed")
				f.unchanged()
				f.noMarker()
				return
			}
			if mode == "capacity" {
				filler := sizedCapacityHistory(t, MaxFile-600-len(f.before), "removed")
				all := append([]byte(nil), f.before...)
				tail := f.request.Tail
				for _, line := range bytes.Split(bytes.TrimSuffix(filler, []byte{'\n'}), []byte{'\n'}) {
					r, e := decode(line)
					if e != nil {
						t.Fatal(e)
					}
					r.Seq = tail.Seq + 1
					r.Prev = tail.Hash
					encoded, e := Encode(r)
					if e != nil {
						t.Fatal(e)
					}
					all = append(all, encoded...)
					tail = Floor{r.Seq, Digest(encoded)}
				}
				if e := os.WriteFile(filepath.Join(f.path, "journal"), all, 0644); e != nil {
					t.Fatal(e)
				}
				f.request.Tail = tail
				_, _, e := f.issuer.PrepareAppend(context.Background(), f.request)
				wantCode(t, e, "journal_capacity_reserve")
				stored, e := os.ReadFile(filepath.Join(f.path, "journal"))
				if e != nil || !bytes.Equal(stored, all) {
					t.Fatal("capacity refusal changed bytes")
				}
				f.noMarker()
				return
			}
			p, g := f.prepare()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var marker []byte
			if mode == "cancelled" {
				cancel()
			}
			if mode == "existing" {
				wantCode(t, makeIntent(f.path, f.policy), "ok")
				marker, _ = os.ReadFile(filepath.Join(f.path, "writer.pending"))
			}
			r, e := AppendPreparedLifetime(ctx, p, g)
			if mode == "valid" {
				f.clean(r, e)
				return
			}
			expected := "journal_lock_timeout"
			if mode == "existing" {
				expected = "journal_writer_pending"
			}
			wantCode(t, e, expected)
			if r.Outcome() != NoWrite || r.ConsumptionAttempted() {
				t.Fatal("premarker progress")
			}
			f.unchanged()
			f.locksFree()
			if mode == "existing" {
				now, _ := os.ReadFile(filepath.Join(f.path, "writer.pending"))
				if !bytes.Equal(now, marker) {
					t.Fatal("existing marker changed")
				}
			} else {
				f.noMarker()
			}
		})
	}
	// Publication failures retain exact incident progress, including unpublished
	// staging; reverse cleanup must not overwrite the last normal phase.
	for _, event := range []string{"before:marker-create", "after:marker-create", "before:marker-write", "after:marker-write", "before:marker-sync", "after:marker-sync", "after:marker-close", "before:marker-publish", "after:marker-publish", "before:marker-parent-sync", "after:marker-parent-sync"} {
		t.Run(event, func(t *testing.T) {
			f := newLifetimeFixture(t)
			f.hooks.at = func(got string) error {
				if got == event {
					return refuse("journal_io")
				}
				return nil
			}
			r, e := f.run()
			wantCode(t, e, "journal_io")
			if r.Outcome() != NoWrite || r.ConsumptionAttempted() || f.ops.consumes != 0 {
				t.Fatal("marker failure reached consumption/write")
			}
			if r.StagingCreated() != (event != "before:marker-create") {
				t.Fatal("lost staging creation evidence")
			}
			published := event == "after:marker-publish" || event == "before:marker-parent-sync" || event == "after:marker-parent-sync"
			if r.MarkerPublished() != published {
				t.Fatal("lost marker publication evidence")
			}
			if r.Phase() != event {
				t.Fatalf("cleanup hid incident phase: %s", r.Phase())
			}
			if published {
				if _, e := os.Stat(filepath.Join(f.path, "writer.pending")); e != nil {
					t.Fatal("published incident lost")
				}
			}
			f.unchanged()
			f.locksFree()
		})
	}

}

// Protected 0750/0640 F identities are distinct and retained; replacement,
// symlink, extra link, package alias and wrong modes/groups fail closed.
func TestAppendPreparedLifetimeFenceIdentity(t *testing.T) {
	for _, mode := range []string{"missing", "symlink", "mode", "directory-mode", "group", "package-alias", "hardlink", "replacement", "directory-replacement", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := newLifetimeFixture(t)
			switch mode {
			case "missing":
				if e := os.Remove(f.fencePath); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(f.fencePath); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(f.path, "gate.lock"), f.fencePath); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := os.Chmod(f.fencePath, 0644); e != nil {
					t.Fatal(e)
				}
			case "directory-mode":
				if e := os.Chmod(filepath.Dir(f.fencePath), 0755); e != nil {
					t.Fatal(e)
				}
			case "group":
				f.ops.binding.Fence.Group++
			case "package-alias":
				f.ops.binding.Fence.PackageFences[0] = f.ops.binding.Fence.FileIdentity
			case "hardlink":
				if e := os.Link(f.fencePath, f.fencePath+".alias"); e != nil {
					t.Fatal(e)
				}
			}
			p, g, e := f.issuer.PrepareAppend(context.Background(), f.request)
			if mode == "replacement" || mode == "directory-replacement" {
				wantCode(t, e, "ok")
				t.Cleanup(func() { _ = p.Close() })
				if mode == "replacement" {
					if e = os.Rename(f.fencePath, f.fencePath+".old"); e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(f.fencePath, nil, 0640); e != nil {
						t.Fatal(e)
					}
				} else {
					dir := filepath.Dir(f.fencePath)
					if e = os.Rename(dir, dir+".old"); e != nil {
						t.Fatal(e)
					}
					if e = os.Mkdir(dir, 0750); e != nil {
						t.Fatal(e)
					}
				}
				r, e := AppendPreparedLifetime(context.Background(), p, g)
				wantCode(t, e, "journal_path_type")
				if r.Outcome() != NoWrite {
					t.Fatal("replacement wrote")
				}
				f.unchanged()
				f.noMarker()
				return
			}
			if mode == "valid" {
				wantCode(t, e, "ok")
				r, e := AppendPreparedLifetime(context.Background(), p, g)
				f.clean(r, e)
				return
			}
			expected := map[string]string{"missing": "journal_path_io", "symlink": "journal_path_io", "mode": "journal_mode", "directory-mode": "journal_mode", "group": "bump_key_admission_unconfirmed", "package-alias": "bump_key_admission_unconfirmed", "hardlink": "journal_path_type"}[mode]
			wantCode(t, e, expected)
			f.unchanged()
			f.noMarker()
		})
	}
}

func lifetimeAssertHeld(t *testing.T, path string, held bool) {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if held {
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			t.Fatalf("expected held %s, got %v", path, e)
		}
	} else {
		if e != nil {
			t.Fatalf("expected free %s: %v", path, e)
		}
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
}

// Real independent descriptions observe gate->data->F and F->data->gate;
// failure immediately after acquisition has the same checked reverse unwind.
func TestAppendPreparedLifetimeOrderAndUnwind(t *testing.T) {
	for _, failure := range []string{"", "acquired:gate.lock", "acquired:data.lock", "before:acquire:F_auth", "acquired:F_auth", "after:verify-current", "before:write"} {
		t.Run(fmt.Sprint("failure=", failure), func(t *testing.T) {
			f := newLifetimeFixture(t)
			p, g := f.prepare()
			var events []string
			f.hooks.at = func(event string) error {
				events = append(events, event)
				gate := filepath.Join(f.path, "gate.lock")
				data := filepath.Join(f.path, "data.lock")
				switch event {
				case "acquired:gate.lock":
					lifetimeAssertHeld(t, gate, true)
					lifetimeAssertHeld(t, data, false)
					lifetimeAssertHeld(t, f.fencePath, false)
				case "acquired:data.lock":
					lifetimeAssertHeld(t, gate, true)
					lifetimeAssertHeld(t, data, true)
					lifetimeAssertHeld(t, f.fencePath, false)
				case "acquired:F_auth", "after:write", "after:journal-sync", "after:verify-post", "after:marker-unlink", "after:provider-finish":
					if !p.pair.resources.fence.held {
						t.Fatal("F ownership not registered before post-acquire work")
					}
					lifetimeAssertHeld(t, gate, true)
					lifetimeAssertHeld(t, data, true)
					lifetimeAssertHeld(t, f.fencePath, true)
				case "after:close:F_auth":
					lifetimeAssertHeld(t, f.fencePath, false)
				case "before:unlock:data.lock":
					lifetimeAssertHeld(t, f.fencePath, false)
					lifetimeAssertHeld(t, gate, true)
				case "before:unlock:gate.lock":
					lifetimeAssertHeld(t, f.fencePath, false)
					lifetimeAssertHeld(t, data, false)
				}
				if failure != "" && event == failure {
					return refuse("journal_io")
				}
				return nil
			}
			r, e := AppendPreparedLifetime(context.Background(), p, g)
			if failure == "" {
				f.clean(r, e)
			} else {
				wantCode(t, e, "journal_io")
				if r.Outcome() != NoWrite {
					t.Fatal("entry error became write")
				}
				f.unchanged()
				f.locksFree()
			}
			index := func(w string) int {
				for i, e := range events {
					if e == w {
						return i
					}
				}
				return -1
			}
			if failure == "" && !(index("acquired:gate.lock") < index("acquired:data.lock") && index("acquired:data.lock") < index("acquired:F_auth") && index("after:provider-finish") < index("before:unlock:F_auth") && index("after:close:F_auth") < index("before:unlock:data.lock") && index("after:close:data.lock") < index("before:unlock:gate.lock")) {
				t.Fatalf("wrong lock order: %v", events)
			}
		})
	}
}

// Consume is called once before write. Any reported partial durability/readback
// failure retains occupied fixture credit/hold and cannot append or refund.
func TestAppendPreparedLifetimeConsume(t *testing.T) {
	for _, failure := range []string{"", "object-sync", "parent-sync", "readback", "post-consume-check"} {
		t.Run("failure="+failure, func(t *testing.T) {
			f := newLifetimeFixture(t)
			if failure != "" {
				f.ops.consume = func(*GuardWindow) error {
					if e := f.ops.retain("occupied"); e != nil {
						return e
					}
					if failure == "post-consume-check" {
						return nil
					}
					return refuse("journal_sync")
				}
				if failure == "post-consume-check" {
					f.ops.check = func(w *GuardWindow) error {
						if w.Phase() == GuardConsumed {
							return lifetimeDenied()
						}
						return nil
					}
				}
			}
			r, e := f.run()
			if failure == "" {
				f.clean(r, e)
				if f.ops.checks != 2 {
					t.Fatal("postconsume check missing")
				}
				return
			}
			expected := "journal_sync"
			if failure == "post-consume-check" {
				expected = "bump_key_admission_unconfirmed"
			}
			wantCode(t, e, expected)
			if r.Outcome() != NoWrite || !r.ConsumptionAttempted() || f.ops.consumes != 1 || f.ops.finishes != 0 {
				t.Fatal("consume progress/count")
			}
			hold, e := os.ReadFile(filepath.Join(f.policy.anchor, "hold"))
			if e != nil || string(hold) != "occupied" {
				t.Fatal("lost occupied hold")
			}
			f.unchanged()
			f.locksFree()
		})
	}
}

// Only journal-issued live phase windows/proofs work; copies, fabricated proofs
// and retained windows cannot authorize later work or restart a budget.
func TestAppendPreparedLifetimeWindow(t *testing.T) {
	f := newLifetimeFixture(t)
	f.ops.check = func(w *GuardWindow) error {
		copy := *w
		wantCode(t, copy.CheckBudget(), "bump_key_admission_unconfirmed")
		wantCode(t, (&GuardWindow{}).CheckBudget(), "bump_key_admission_unconfirmed")
		wantCode(t, w.CheckProof(AppendProof{}), "bump_key_admission_unconfirmed")
		if w.Binding().Request != f.request {
			t.Fatal("window binding changed")
		}
		left, e := w.Remaining()
		if e != nil || left <= 0 || left > 1000*1000000 {
			t.Fatal("bad remaining")
		}
		return nil
	}
	f.ops.finish = func(w *GuardWindow, p AppendProof) error {
		wantCode(t, w.CheckProof(AppendProof{}), "bump_key_admission_unconfirmed")
		wantCode(t, w.CheckProof(p), "ok")
		if p.Checkpoint().Seq != f.request.Tail.Seq+1 {
			t.Fatal("wrong proof")
		}
		return f.ops.retain("retained-active")
	}
	r, e := f.run()
	f.clean(r, e)
	for _, w := range f.ops.windows {
		wantCode(t, w.CheckBudget(), "bump_key_admission_unconfirmed")
		_, e := w.Remaining()
		wantCode(t, e, "bump_key_admission_unconfirmed")
		if w.Binding() != (AppendBinding{}) {
			t.Fatal("stale window retains binding access")
		}
	}
}
