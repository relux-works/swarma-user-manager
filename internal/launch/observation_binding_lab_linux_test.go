//go:build linux && manager_lab

package launch

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
)

func labBindingSocketExchange(test *testing.T, source *labObservationSource, request []byte) []byte {
	test.Helper()
	clock, err := labBootNanos()
	if err != nil {
		test.Fatal(err)
	}
	source.now = func() (int64, error) { return clock, nil }
	client, connection := observationConnections(test)
	server := &labObservationServer{source: source}
	deadline, admitted := server.admit()
	if !admitted {
		test.Fatal("binding join connection refused before dispatch")
	}
	done := make(chan struct{})
	go func() { defer close(done); server.handle(connection, deadline) }()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		test.Fatal(err)
	}
	frame := observationRequestFrame(request)
	if count, err := client.Write(frame); err != nil || count != len(frame) {
		test.Fatal("binding join request write failed", err)
	}
	if err := client.CloseWrite(); err != nil {
		test.Fatal(err)
	}
	answer, err := io.ReadAll(client)
	<-done
	if err != nil {
		test.Fatal("binding join exchange did not close cleanly", err)
	}
	return answer
}

func labBindingSocketControl(test *testing.T, fixture *fixture, source *labObservationSource, request []byte, sequence int64) labObservationResponse {
	test.Helper()
	answer := labBindingSocketExchange(test, source, request)
	var record labObservationResponse
	if len(answer) < 4 || int(binary.BigEndian.Uint32(answer[:4])) != len(answer)-4 || manager.Strict(answer[4:], &record) != nil {
		test.Fatal("restored native join control lost its frame")
	}
	if !record.Complete || record.Sequence != sequence || record.Start.Owner != source.binding.Owner || record.Start.UID != fixtureUID || record.Start.Generation != fixtureGen || record.Start.OperationID != "observation-launch" || record.Start.StartID != "EX-1" || record.Manager.BootID != fixtureBoot || !record.Store.GenerationCurrent || record.SequenceGeneration != source.binding.StoreGeneration || len(record.Receipts) != 1 || record.Receipts[0].BootID != fixtureBoot {
		test.Fatal("restored native join control changed its binding")
	}
	counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
	if err != nil || counter.Sequence != sequence || fixture.seams.execs != 1 {
		test.Fatal("native join control did not reserve exactly one sequence without execution")
	}
	return record
}

// Claim: each structurally valid foreign-owner, duplicate-invalidation, daemon-as-start or receipt-only foreign-boot join emits no socket frame or sequence; restoring it admits the same start through SO_PEERCRED, framing and the native lock.
func TestLabObservationBindingJoin(test *testing.T) {
	for _, gate := range []string{"owner", "duplicate-invalidation", "daemon-uid-start", "receipt-boot"} {
		test.Run(gate, func(test *testing.T) {
			fixture, source, request := observationFixture(test)
			path := filepath.Join(fixture.root, "lib/user-manager/launch/effects.json")
			mode := os.FileMode(0600)
			switch gate {
			case "duplicate-invalidation":
				path = filepath.Join(fixture.root, "lib/user-manager/launch/invalidations")
				line, err := EncodeLine(Invalidation{InvalidationFormat, fixtureGen, "EX-1", "fixture-revoked", fixtureBoot, 1001})
				if err != nil {
					test.Fatal(err)
				}
				write(test, path, line, mode)
			case "receipt-boot":
				write(test, filepath.Join(fixture.root, "lib/user-manager/launch/debits"), []byte{}, 0600)
				path = filepath.Join(fixture.root, "lib/user-manager/receipts", fixtureGen, "EX-1.json")
				mode = 0644
			}
			original, err := os.ReadFile(path)
			if err != nil {
				test.Fatal(err)
			}
			control := labBindingSocketControl(test, fixture, source, request, 2)
			if gate == "duplicate-invalidation" && len(control.Invalidations) != 1 || gate == "receipt-boot" && len(control.Debits) != 0 {
				test.Fatal("native join control did not isolate the selected evidence")
			}
			var altered []byte
			switch gate {
			case "owner", "daemon-uid-start":
				effects := fixture.effects()
				if gate == "owner" {
					effects.Launches[0].Owner = "fixture-other"
					effects.Launches[0].Admitted.Principal = "fixture-other"
				} else {
					effects.Launches[0].UID = source.binding.DaemonUID
				}
				altered, err = effectBytes(effects)
			case "duplicate-invalidation":
				altered = append(append([]byte{}, original...), original...)
				decoded, decodeErr := DecodeInvalidations(altered)
				if decodeErr != nil || len(decoded) != 2 || decoded[0] != decoded[1] {
					test.Fatal("duplicate witness never reached the observation join")
				}
			case "receipt-boot":
				receipt := fixture.receipts()[0]
				receipt.BootID = "22222222-2222-2222-2222-222222222222"
				altered, err = manager.ObjectBytes(receipt)
			}
			if err != nil {
				test.Fatal(err)
			}
			write(test, path, altered, mode)
			fixture.effects()
			fixture.receipts()
			if answer := labBindingSocketExchange(test, source, request); len(answer) != 0 {
				test.Fatal("unsafe native join produced a socket frame", gate)
			}
			counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
			if err != nil || counter.Sequence != 2 || source.failed || fixture.seams.execs != 1 {
				test.Fatal("refused native join reserved a sequence or changed execution")
			}
			preserved, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(preserved, altered) {
				test.Fatal("refused native join rewrote its evidence")
			}
			write(test, path, original, mode)
			restored := labBindingSocketControl(test, fixture, source, request, 3)
			if len(restored.Invalidations) != len(control.Invalidations) || len(restored.Debits) != len(control.Debits) || restored.Store.EffectsSHA256 != control.Store.EffectsSHA256 || restored.Store.ReceiptsSHA256 != control.Store.ReceiptsSHA256 || restored.Store.InvalidationsHead != control.Store.InvalidationsHead || restored.Store.DebitsHead != control.Store.DebitsHead {
				test.Fatal("restored native join control lost evidence")
			}
		})
	}
}
