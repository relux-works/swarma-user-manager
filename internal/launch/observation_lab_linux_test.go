//go:build linux && manager_lab

package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

func observationFixture(test *testing.T) (*fixture, *labObservationSource, []byte) {
	test.Helper()
	fixture, _, dependencies := labMappingFixture(test)
	binding := LabObservationBinding{labObservationBindingFormat, int64(os.Getuid()), int64(os.Getgid()), "fixture-manager", strings.Repeat("b", 64), strings.Repeat("c", 32), strings.Repeat("d", 32), fixture.caller.Principal, fixtureGen}
	created, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
	if err != nil {
		test.Fatal(err)
	}
	empty := manager.State{Format: manager.StateFormat, Floor: genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash}, Cursor: fixture.policy.UIDMin, Effects: []manager.Effect{}, OSRecords: []manager.OSRecord{}, Revision: 1}
	inner, _ := manager.ObjectBytes(empty)
	fresh, _ := manager.ObjectBytes(managerEnvelope{manager.StoreFormat, empty, manager.DigestBytes(inner)})
	if err := manager.WriteProtected(fixture.store.journal, "effects.json", fresh, fixture.owner); err != nil {
		test.Fatal(err)
	}
	if err := fixture.store.provisionLabObservation(binding.StoreGeneration, &memJournal{}); err != nil {
		test.Fatal("observation install", err)
	}
	if err := manager.WriteProtected(fixture.store.journal, "effects.json", created, fixture.owner); err != nil {
		test.Fatal(err)
	}
	if err := fixture.store.installLabObservationBinding(binding); err != nil {
		test.Fatal(err)
	}
	result := (Launcher{dependencies}).Run(context.Background(), fixture.launchRequest("observation-launch", nil), fixture.invocation(fixture.caller))
	if !result.OK {
		test.Fatal("composed lab start refused", errCode(result))
	}
	source := &labObservationSource{store: fixture.store, journal: fixture.journal, policy: fixture.policy, binding: binding, boot: fixtureBoot, now: func() (int64, error) { return int64(2 * time.Second), nil }}
	request, err := manager.ObjectBytes(labObservationRequest{labObservationRequestFormat, "observation-launch", "EX-1"})
	if err != nil {
		test.Fatal(err)
	}
	return fixture, source, request
}

func observeFixture(test *testing.T, source *labObservationSource, request []byte) labObservationResponse {
	test.Helper()
	raw, err := source.observe(context.Background(), request, int64(3*time.Second))
	if err != nil {
		test.Fatal("native observation control refused", err)
	}
	var response labObservationResponse
	if manager.Strict(raw, &response) != nil {
		test.Fatal("response is not closed canonical bytes")
	}
	return response
}

// Claim: a composed tagged start produces the complete native join and increasing store-scoped sequences without changing the compared native snapshot.
func TestLabObservationNativeJoin(test *testing.T) {
	fixture, source, request := observationFixture(test)
	var before genjournal.View
	if err := fixture.journal.Checkpoint(context.Background(), fixture.floor, func(view genjournal.View) error { before = view; return nil }); err != nil {
		test.Fatal(err)
	}
	snapshot, err := fixture.store.labSnapshot(fixtureGen, before)
	if err != nil {
		test.Fatal(err)
	}
	first := observeFixture(test, source, request)
	second := observeFixture(test, source, request)
	if first.Sequence != 2 || second.Sequence != 3 || first.SequenceGeneration != source.binding.StoreGeneration || !first.Complete || !first.Store.GenerationCurrent {
		test.Fatal("observation sequence/currentness not bound")
	}
	if first.Start.OperationID != "observation-launch" || first.Start.StartID != "EX-1" || first.Start.Owner != fixture.caller.Principal || first.Start.Generation != fixtureGen || first.Start.UID != fixtureUID || first.Start.Phase != PhaseAdmitted || first.Start.PlanSHA256 != "sha256:"+digestOf(fixture.plan) {
		test.Fatal("native start projection changed")
	}
	if len(first.Receipts) != 1 || len(first.Debits) != 1 || len(first.Invalidations) != 0 || len(first.Stops) != 0 || first.Receipts[0].PID != first.Debits[0].PID {
		test.Fatal("native join incomplete")
	}
	if first.Manager.UID != 0 || first.Manager.BootID != fixtureBoot || first.Manager.ExecutableSHA256 != "sha256:"+source.binding.ExecutableSHA256 || first.Store.ManagerHead.SHA256 != "sha256:"+before.Tail.Hash || first.Store.DebitsHead.SHA256 != labDigest(snapshot.Debits) || first.Store.EffectsSHA256 != labDigest(snapshot.Effects) {
		test.Fatal("native manager/store proof changed")
	}
	after, err := fixture.store.labSnapshot(fixtureGen, before)
	if err != nil || !reflect.DeepEqual(snapshot, after) {
		test.Fatal("sequence reservation changed native snapshot")
	}
	if fixture.seams.execs != 1 || len(fixture.debits()) != 1 {
		test.Fatal("observation reran launch")
	}
}

// Claim: every selected invalidation and pending or terminal stop is projected, including a different stop request ID; this is projection, not stop authorization qualification.
func TestLabObservationNarrowingProjection(test *testing.T) {
	for _, phase := range []string{PhaseAdmitted, PhaseTerminal} {
		test.Run(phase, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			control := observeFixture(test, source, request)
			if len(control.Stops) != 0 || len(control.Invalidations) != 0 {
				test.Fatal("narrowing control not empty")
			}
			effects := fixture.effects()
			stop := StopEffect{Owner: fixture.caller.Principal, Admitted: fixture.caller, RequestID: "other-stop", Args: StopArgs{fixtureGen, "EX-1", 1}, Phase: phase}
			if phase == PhaseTerminal {
				stop.Result = &StopResult{ExecutionID: "EX-1", StoppedAt: "2026-11-20T00:00:00Z", Receipt: StopReceipt{}}
			}
			effects.Stops = append(effects.Stops, stop)
			effects.Revision++
			if err := fixture.store.Save(effects); err != nil {
				test.Fatal(err)
			}
			for _, reason := range []string{"fixture-revoked", "fixture-changed"} {
				if err := fixture.store.Invalidate(Invalidation{InvalidationFormat, fixtureGen, "EX-1", reason, fixtureBoot, 1001}); err != nil {
					test.Fatal(err)
				}
			}
			observed := observeFixture(test, source, request)
			if len(observed.Stops) != 1 || observed.Stops[0].Phase != phase || observed.Stops[0].OperationID != "other-stop" || len(observed.Invalidations) != 2 || observed.Store.EffectsSHA256 == control.Store.EffectsSHA256 {
				test.Fatal("pending stop or invalidation hidden")
			}
		})
	}
}

// Claim: the native account predicate distinguishes historical successful creation from the same account retiring or being superseded.
func TestLabObservationCurrentAccount(test *testing.T) {
	for _, state := range []string{"retiring", "superseded"} {
		test.Run(state, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			if !observeFixture(test, source, request).Store.GenerationCurrent {
				test.Fatal("current control missing")
			}
			fixture.appendJournal(fixtureGen, "retiring")
			if state == "superseded" {
				fixture.appendJournal(fixtureGen, "removed")
				fixture.appendJournal(strings.Repeat("e", 32), "creating")
				fixture.appendJournal(strings.Repeat("e", 32), "active")
			}
			if observeFixture(test, source, request).Store.GenerationCurrent {
				test.Fatal("historical account reported current")
			}
		})
	}
}

// Claim: missing, torn, conflicting or replaced native evidence closes the actual locked collector beside an admitted complete control.
func TestLabObservationEvidenceRefusals(test *testing.T) {
	cases := map[string]func(*fixture, *labObservationSource){
		"store-proof": func(fixture *fixture, _ *labObservationSource) {
			raw, _ := manager.ObjectBytes(labObservationStoreProof{"station-lab-observation-store/1", strings.Repeat("f", 32)})
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-store.json"), raw, 0600)
		},
		"missing-debits": func(fixture *fixture, _ *labObservationSource) {
			if err := os.Remove(filepath.Join(fixture.root, "lib/user-manager/launch/debits")); err != nil {
				test.Fatal(err)
			}
		},
		"torn-debits": func(fixture *fixture, _ *labObservationSource) {
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/debits"), []byte("{"), 0600)
		},
		"duplicate-debit": func(fixture *fixture, _ *labObservationSource) {
			raw, err := EncodeLine(fixture.debits()[0])
			if err != nil {
				test.Fatal(err)
			}
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/debits"), append(raw, raw...), 0600)
		},
		"incarnation": func(fixture *fixture, _ *labObservationSource) {
			debit := fixture.debits()[0]
			debit.StartTime++
			raw, _ := EncodeLine(debit)
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/debits"), raw, 0600)
		},
		"counter-generation": func(fixture *fixture, source *labObservationSource) {
			raw, _ := manager.ObjectBytes(labObservationCounter{labObservationCounterFormat, strings.Repeat("f", 32), 9})
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-counter.json"), raw, 0600)
		},
		"counter-regression": func(fixture *fixture, source *labObservationSource) {
			raw, _ := manager.ObjectBytes(labObservationCounter{labObservationCounterFormat, source.binding.StoreGeneration, 1})
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-counter.json"), raw, 0600)
		},
		"missing-counter": func(fixture *fixture, _ *labObservationSource) {
			if err := os.Remove(filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-counter.json")); err != nil {
				test.Fatal(err)
			}
		},
		"changed-binding": func(fixture *fixture, source *labObservationSource) {
			binding := source.binding
			binding.DaemonUID++
			raw, _ := manager.ObjectBytes(binding)
			write(test, filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-binding.json"), raw, 0600)
		},
		"replaced-directory": func(fixture *fixture, _ *labObservationSource) {
			path := filepath.Join(fixture.root, "lib/user-manager/launch")
			if err := os.Rename(path, path+"-old"); err != nil {
				test.Fatal(err)
			}
			mkdir(test, path, 0700)
		},
	}
	for name, change := range cases {
		test.Run(name, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			observeFixture(test, source, request)
			change(fixture, source)
			if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
				test.Fatal("bad native evidence produced a success frame")
			}
			if fixture.seams.execs != 1 {
				test.Fatal("refusal retried execution")
			}
		})
	}
}

// Claim: shared-lock contention, request or hold equality, absent policy and counter exhaustion refuse without resetting the counter; each has a complete control.
func TestLabObservationBounds(test *testing.T) {
	for _, bound := range []string{"lock", "deadline", "hold", "native-hold", "policy", "exhausted", "clock"} {
		test.Run(bound, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			observeFixture(test, source, request)
			deadline := int64(3 * time.Second)
			switch bound {
			case "lock":
				unlock, err := fixture.store.Lock(context.Background(), 0)
				if err != nil {
					test.Fatal(err)
				}
				defer unlock()
			case "deadline":
				deadline = int64(2 * time.Second)
			case "hold", "native-hold":
				increment := int64(25 * time.Millisecond)
				if bound == "native-hold" {
					source.policy.Limits.LockMS = 1
					increment = int64(time.Millisecond)
				}
				now := int64(2 * time.Second)
				source.now = func() (int64, error) { value := now; now += increment; return value, nil }
			case "policy":
				source.policy.Limits.LockMS = 0
			case "exhausted":
				raw, _ := manager.ObjectBytes(labObservationCounter{labObservationCounterFormat, source.binding.StoreGeneration, labObservationMaxSequence})
				write(test, filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-counter.json"), raw, 0600)
			case "clock":
				now := int64(2 * time.Second)
				source.now = func() (int64, error) { value := now; now--; return value, nil }
			}
			if raw, err := source.observe(context.Background(), request, deadline); err == nil || raw != nil {
				test.Fatal("native observation bound bypassed")
			}
		})
	}
}

// Claim: repeated observation provisioning cannot reset its counter, all four metadata modes are 0600, and an instance is consumed once; this is not the full helper setup.
func TestLabObservationFormatOwnedSetup(test *testing.T) {
	fixture, source, request := observationFixture(test)
	before := observeFixture(test, source, request)
	if err := fixture.store.provisionLabObservation(source.binding.StoreGeneration, fixture.journal); err == nil {
		test.Fatal("repeat setup reset lab metadata")
	}
	after := observeFixture(test, source, request)
	if after.Sequence != before.Sequence+1 {
		test.Fatal("setup reset observation sequence")
	}
	if err := fixture.store.labBeginObservation(source.binding); err != nil {
		test.Fatal("fresh instance rejected", err)
	}
	if err := fixture.store.labBeginObservation(source.binding); err == nil {
		test.Fatal("same instance reused across restart")
	}
	for _, name := range []string{"binding", "counter", "instance", "store"} {
		status, err := os.Stat(filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-"+name+".json"))
		if err != nil || status.Mode().Perm() != 0600 {
			test.Fatal("lab setup mode changed")
		}
	}
}

// Claim: C0c request closure, every fixed-label literal operator and all native-id byte/length operators reject only the forbidden values beside valid controls.
func TestLabObservationRequestCatalogue(test *testing.T) {
	control := map[string]any{"format": labObservationRequestFormat, "operation_id": "fixture.Operation_9", "start_id": "fixture.Start_9"}
	check := func(record any, valid bool) {
		test.Helper()
		controlRaw, _ := manager.ObjectBytes(control)
		if _, err := parseLabObservationRequest(controlRaw); err != nil {
			test.Fatal("catalogue valid control rejected")
		}
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(record); err != nil {
			test.Fatal(err)
		}
		raw := bytes.TrimSuffix(encoded.Bytes(), []byte{10})
		_, err := parseLabObservationRequest(raw)
		if (err == nil) != valid {
			test.Fatalf("request catalogue verdict=%v want=%v", err, valid)
		}
	}
	clone := func() map[string]any {
		result := map[string]any{}
		for name, value := range control {
			result[name] = value
		}
		return result
	}
	for name, value := range control {
		for _, replacement := range observationLabelOperators(name) {
			record := clone()
			delete(record, name)
			record[replacement] = value
			check(record, false)
			alias := clone()
			alias[replacement] = value
			check(alias, false)
		}
		for _, replacement := range []any{nil, true, int64(1), []any{}, map[string]any{}} {
			record := clone()
			record[name] = replacement
			check(record, false)
		}
		record := clone()
		delete(record, name)
		check(record, false)
	}
	for _, replacement := range observationLiteralOperators(labObservationRequestFormat) {
		record := clone()
		record["format"] = replacement
		check(record, false)
	}
	for _, name := range []string{"operation_id", "start_id"} {
		for _, seed := range []string{"a", "A", "0", "a.B_9", strings.Repeat("a", 64)} {
			for _, replacement := range append(observationLiteralOperators(seed), seed) {
				record := clone()
				record[name] = replacement
				check(record, observationNativeIDOracle(replacement))
			}
		}
		for _, replacement := range []string{"a/", "a\x00", "é", "aK", "aı", "aſ", "a．b", "a_b", "A.B-9"} {
			record := clone()
			record[name] = replacement
			check(record, observationNativeIDOracle(replacement))
		}
		for _, length := range []int{0, 1, 2, 63, 64, 65} {
			record := clone()
			record[name] = strings.Repeat("a", length)
			check(record, length >= 1 && length <= 64)
		}
		for _, offset := range []int{0, 2, 4} {
			for character := 0; character < 256; character++ {
				value := []byte("a.B_9")
				value[offset] = byte(character)
				allowed := (character >= 65 && character <= 90) || (character >= 97 && character <= 122) || (character >= 48 && character <= 57) || offset != 0 && (character == 46 || character == 95 || character == 45)
				record := clone()
				record[name] = string(value)
				check(record, allowed)
			}
		}
	}
	for _, name := range []string{"path", "uid", "generation", "plan", "ledger"} {
		record := clone()
		record[name] = "fixture"
		check(record, false)
	}
	raw, _ := manager.ObjectBytes(control)
	for _, wrong := range []any{nil, true, int64(1), "fixture", []any{control}, map[string]any{"args": control}} {
		check(wrong, false)
	}
	for name, value := range control {
		key, _ := json.Marshal(name)
		member, _ := json.Marshal(value)
		duplicate := append(append(append(append([]byte("{"), key...), 58), member...), 44)
		duplicate = append(duplicate, raw[1:]...)
		if _, err := parseLabObservationRequest(raw); err != nil {
			test.Fatal("duplicate valid control refused")
		}
		if _, err := parseLabObservationRequest(duplicate); err == nil {
			test.Fatal("duplicate member admitted")
		}
	}
	for _, noncanonical := range [][]byte{append(append([]byte{}, raw...), 10), append([]byte(" "), raw...), bytes.Replace(raw, []byte("\"format\":"), []byte("\"format\":null,\"format\":"), 1), bytes.Replace(raw, []byte("fixture"), []byte("\\u0066ixture"), 1)} {
		if _, err := parseLabObservationRequest(noncanonical); err == nil {
			test.Fatal("noncanonical request admitted")
		}
	}
	var roundtrip map[string]any
	if json.Unmarshal(raw, &roundtrip) != nil {
		test.Fatal("invalid test control")
	}
	check(roundtrip, true)
}

// Claim: lookup changes to either native ID cannot retarget the one composed start or reserve a new observation sequence.
func TestLabObservationRequestJoin(test *testing.T) {
	for _, selector := range []string{"operation", "start", "both"} {
		test.Run(selector, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			control := observeFixture(test, source, request)
			altered, err := parseLabObservationRequest(request)
			if err != nil {
				test.Fatal(err)
			}
			if selector != "start" {
				altered.OperationID = "fixture-other"
			}
			if selector != "operation" {
				altered.StartID = "fixture-other"
			}
			raw, _ := manager.ObjectBytes(altered)
			if answer, err := source.observe(context.Background(), raw, int64(3*time.Second)); err == nil || answer != nil {
				test.Fatal("native IDs retargeted a start")
			}
			counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
			if err != nil || counter.Sequence != control.Sequence {
				test.Fatal("failed lookup reserved a sequence")
			}
		})
	}
}

// Claim: changing any compared native object during sequence reservation is UNKNOWN and sticky, including a same-byte inode replacement; fixture clocks do not qualify native I/O timing.
func TestLabObservationSnapshotReservation(test *testing.T) {
	for _, object := range []string{"manager", "effects", "debits", "invalidations", "receipts", "inode", "rewrite", "binding"} {
		test.Run(object, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			control := observeFixture(test, source, request)
			calls := 0
			source.now = func() (int64, error) {
				calls++
				if calls == 3 {
					switch object {
					case "manager":
						raw, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
						if err != nil {
							test.Fatal(err)
						}
						state, err := manager.LabObservationState(raw)
						if err != nil {
							test.Fatal(err)
						}
						state.Revision++
						inner, _ := manager.ObjectBytes(state)
						encoded, _ := manager.ObjectBytes(managerEnvelope{manager.StoreFormat, state, manager.DigestBytes(inner)})
						if err := manager.WriteProtected(fixture.store.journal, "effects.json", encoded, fixture.owner); err != nil {
							test.Fatal(err)
						}
					case "effects":
						effects := fixture.effects()
						effects.Revision++
						if err := fixture.store.Save(effects); err != nil {
							test.Fatal(err)
						}
					case "debits":
						debit := fixture.debits()[0]
						debit.ExecutionID = "fixture-other"
						writer, err := fixture.store.appendHandle("debits")
						if err != nil {
							test.Fatal(err)
						}
						err = appendLine(writer, debit)
						writer.Close()
						if err != nil {
							test.Fatal(err)
						}
					case "invalidations":
						if err := fixture.store.Invalidate(Invalidation{InvalidationFormat, fixtureGen, "fixture-other", "fixture-revoked", fixtureBoot, 1001}); err != nil {
							test.Fatal(err)
						}
					case "receipts":
						receipt := fixture.receipts()[0]
						receipt.ExecutionID = "fixture-other"
						if err := fixture.store.WriteReceipt(fixtureGen, receipt); err != nil {
							test.Fatal(err)
						}
					case "inode":
						raw, err := manager.ReadProtected(fixture.store.dir, "debits", fixture.owner, MaxLedger)
						if err != nil {
							test.Fatal(err)
						}
						if err := manager.WriteProtected(fixture.store.dir, "debits", raw, fixture.owner); err != nil {
							test.Fatal(err)
						}
					case "rewrite":
						path := filepath.Join(fixture.root, "lib/user-manager/launch/debits")
						raw, err := os.ReadFile(path)
						if err != nil {
							test.Fatal(err)
						}
						file, err := os.OpenFile(path, os.O_WRONLY, 0)
						if err != nil {
							test.Fatal(err)
						}
						written, writeErr := file.WriteAt(raw, 0)
						syncErr := file.Sync()
						closeErr := file.Close()
						if writeErr != nil || syncErr != nil || closeErr != nil || written != len(raw) {
							test.Fatal("rewrite fault failed")
						}
					case "binding":
						binding := source.binding
						binding.InstanceID = strings.Repeat("e", 32)
						encoded, _ := manager.ObjectBytes(binding)
						if err := manager.WriteProtected(fixture.store.dir, "lab-observation-binding.json", encoded, fixture.owner); err != nil {
							test.Fatal(err)
						}
					}
				}
				return int64(2 * time.Second), nil
			}
			if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
				test.Fatal("changed native snapshot published")
			}
			if calls < 3 {
				test.Fatal("snapshot fault was not applied")
			}
			counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
			if err != nil || counter.Sequence != control.Sequence+1 {
				test.Fatal("failed observation refunded reserved sequence")
			}
			if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
				test.Fatal("uncertain reservation reopened")
			}
		})
	}
}

// Claim: replacing effects.lock after acquisition but before the first snapshot cannot turn a different inode into the held authority; the sequence remains spent and UNKNOWN is sticky.
func TestLabObservationLockReplacement(test *testing.T) {
	fixture, source, request := observationFixture(test)
	control := observeFixture(test, source, request)
	calls := 0
	source.now = func() (int64, error) {
		calls++
		if calls == 2 {
			if err := manager.WriteProtected(fixture.store.journal, "effects.lock", []byte{}, fixture.owner); err != nil {
				test.Fatal(err)
			}
		}
		return int64(2 * time.Second), nil
	}
	if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
		test.Fatal("replaced acquisition lock published snapshot")
	}
	counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
	if calls < 2 || err != nil || counter.Sequence != control.Sequence+1 || !source.failed {
		test.Fatal("lock replacement did not preserve uncertain reservation")
	}
	if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
		test.Fatal("lock replacement reopened observation")
	}
	if fixture.seams.execs != 1 || len(fixture.debits()) != 1 {
		test.Fatal("lock replacement retried start")
	}
}

// Claim: a real denied atomic counter replacement produces sticky UNKNOWN without refund or retry after write access is restored; this does not emulate a power failure.
func TestLabObservationCounterPersistence(test *testing.T) {
	fixture, source, request := observationFixture(test)
	control := observeFixture(test, source, request)
	calls := 0
	directory := filepath.Join(fixture.root, "lib/user-manager/launch")
	defer os.Chmod(directory, 0700)
	source.now = func() (int64, error) {
		calls++
		if calls == 3 {
			if err := os.Chmod(directory, 0500); err != nil {
				test.Fatal(err)
			}
		}
		return int64(2 * time.Second), nil
	}
	if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil || !source.failed {
		test.Fatal("uncertain persistence did not close admission")
	}
	if calls < 3 {
		test.Fatal("counter replacement fault was not applied")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		test.Fatal(err)
	}
	counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
	if err != nil || counter.Sequence != control.Sequence {
		test.Fatal("failed replacement changed its counter")
	}
	if raw, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil || raw != nil {
		test.Fatal("uncertain persistence reopened")
	}
}

// Claim: an already-used native store cannot acquire a new lab generation proof or counter; the separate fresh-install control serves complete observations.
func TestLabObservationFreshStore(test *testing.T) {
	_, source, request := observationFixture(test)
	observeFixture(test, source, request)
	for _, launched := range []bool{false, true} {
		fixture := newFixture(test)
		if launched {
			fixture.launched()
		}
		before, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
		if err != nil {
			test.Fatal(err)
		}
		if err := fixture.store.provisionLabObservation(strings.Repeat("d", 32), fixture.journal); err == nil {
			test.Fatal("existing native store adopted by lab")
		}
		after, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
		if err != nil || !bytes.Equal(before, after) {
			test.Fatal("refused install changed native manager state")
		}
		for _, name := range []string{"store", "counter", "binding", "instance"} {
			if _, err := os.Lstat(filepath.Join(fixture.root, "lib/user-manager/launch/lab-observation-"+name+".json")); !os.IsNotExist(err) {
				test.Fatal("refused install left lab metadata")
			}
		}
	}
	fixture := newFixture(test)
	raw, err := manager.ReadProtected(fixture.store.journal, "effects.json", fixture.owner, 8*1024*1024)
	if err != nil {
		test.Fatal(err)
	}
	state, err := manager.LabObservationState(raw)
	if err != nil {
		test.Fatal(err)
	}
	state.Floor = genjournal.Floor{Seq: 0, Hash: genjournal.ZeroHash}
	inner, _ := manager.ObjectBytes(state)
	encoded, _ := manager.ObjectBytes(managerEnvelope{manager.StoreFormat, state, manager.DigestBytes(inner)})
	if err := manager.WriteProtected(fixture.store.journal, "effects.json", encoded, fixture.owner); err != nil {
		test.Fatal(err)
	}
	if err := fixture.store.provisionLabObservation(strings.Repeat("d", 32), &memJournal{}); err == nil {
		test.Fatal("existing native store adopted by lab")
	}
}
