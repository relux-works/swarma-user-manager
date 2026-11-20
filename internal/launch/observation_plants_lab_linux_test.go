//go:build linux && manager_lab

package launch

import (
	"strings"
	"testing"
)

// Claim: each observation source-overlay gate deletion fails the named assertion with a green exact-source baseline and an unaffected parser or native control.
func TestLabObservationPlants(test *testing.T) {
	plants := []mappingProfilePlant{
		{name: "observation-request-closure", source: "observation_lab_linux.go", before: "manager.Strict(raw, &request) != nil", after: "func() bool { _ = manager.Strict(raw, &request); return false }()", test: "TestLabObservationRequestCatalogue", assertion: "request catalogue verdict"},
		{name: "observation-request-literal", source: "observation_lab_linux.go", before: "request.Format != labObservationRequestFormat", after: "false", test: "TestLabObservationRequestCatalogue", assertion: "request catalogue verdict"},
		{name: "observation-request-native-id", source: "observation_lab_linux.go", before: "!manager.ValidRequestID(request.StartID)", after: "false", test: "TestLabObservationRequestCatalogue", assertion: "request catalogue verdict"},
		{name: "observation-request-join", source: "observation_lab_linux.go", before: "effect.RequestID == request.OperationID && effect.ExecutionID == request.StartID", after: "true", test: "TestLabObservationRequestJoin/operation", assertion: "native IDs retargeted a start"},
		{name: "observation-current-account", source: "observation_lab_linux.go", before: "current = current && latest", after: "current = current && latest || true", test: "TestLabObservationCurrentAccount/retiring", assertion: "historical account reported current"},
		{name: "observation-pending-stop", source: "observation_lab_linux.go", before: "stop.Args.Generation == start.Generation && stop.Args.ExecutionID == start.ExecutionID", after: "false", test: "TestLabObservationNarrowingProjection/admitted", assertion: "pending stop or invalidation hidden"},
		{name: "observation-invalidation", source: "observation_lab_linux.go", before: "invalidation.Generation == start.Generation && invalidation.ExecutionID == start.ExecutionID", after: "false", test: "TestLabObservationNarrowingProjection/admitted", assertion: "pending stop or invalidation hidden"},
		{name: "observation-incarnation", source: "observation_lab_linux.go", before: "receipt.StartTime != debit.StartTime", after: "false", test: "TestLabObservationEvidenceRefusals/incarnation", assertion: "bad native evidence produced a success frame"},
		{name: "observation-counter-generation", source: "observation_lab_linux.go", before: "counter.Generation != generation", after: "false", test: "TestLabObservationEvidenceRefusals/counter-generation", assertion: "bad native evidence produced a success frame"},
		{name: "observation-counter-regression", source: "observation_lab_linux.go", before: "counter.Sequence < source.lastSequence", after: "false", test: "TestLabObservationEvidenceRefusals/counter-regression", assertion: "bad native evidence produced a success frame"},
		{name: "observation-counter-reservation", source: "observation_lab_linux.go", before: "counter.Sequence++", after: "counter.Sequence += 0", test: "TestLabObservationNativeJoin", assertion: "observation sequence/currentness not bound"},
		{name: "observation-snapshot", source: "observation_lab_linux.go", before: "!reflect.DeepEqual(before, after)", after: "!reflect.DeepEqual(before, after) && false", test: "TestLabObservationSnapshotReservation/inode", assertion: "changed native snapshot published"},
		{name: "observation-object-stamp", source: "observation_lab_linux.go", before: "status.Size, status.Mode, status.Uid, status.Gid, status.Mtim, status.Ctim", after: "0, 0, 0, 0, unix.Timespec{}, unix.Timespec{}", test: "TestLabObservationSnapshotReservation/rewrite", assertion: "changed native snapshot published"},
		{name: "observation-lock-replacement", source: "observation_lab_linux.go", before: "before.Objects[\"lock\"] != lockObject || after.Objects[\"lock\"] != lockObject", after: "false", test: "TestLabObservationLockReplacement", assertion: "replaced acquisition lock published snapshot"},
		{name: "observation-lock-hold", source: "observation_lab_linux.go", before: "now-acquired >= limit", after: "now-acquired < -limit", test: "TestLabObservationBounds/hold", assertion: "native observation bound bypassed"},
		{name: "observation-deadline", source: "observation_lab_linux.go", before: "now >= deadline", after: "now > deadline", test: "TestLabObservationBounds/deadline", assertion: "native observation bound bypassed"},
		{name: "observation-peer", source: "observation_server_lab_linux.go", before: "int64(peer.Uid) != expected", after: "false", test: "TestLabObservationKernelPeer", assertion: "different kernel peer UID admitted"},
		{name: "observation-eof", source: "observation_server_lab_linux.go", before: "length < 1 || length > 4096 || used != 4+length", after: "length < 1 || length > 4096 || used < 4+length", test: "TestLabObservationFrameEOF", assertion: "framing accepted trailing bytes"},
		{name: "observation-ancillary", source: "observation_server_lab_linux.go", before: "ancillary != 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0", after: "flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0", test: "TestLabObservationTransport/ancillary", assertion: "forbidden transport produced a response"},
		{name: "observation-concurrency", source: "observation_server_lab_linux.go", before: "server.busy || now < server.notBefore", after: "now < server.notBefore", test: "TestLabObservationLoad", assertion: "concurrent observation admitted"},
		{name: "observation-cooldown", source: "observation_server_lab_linux.go", before: "server.busy || now < server.notBefore", after: "server.busy", test: "TestLabObservationLoad", assertion: "startup cooldown bypassed"},
		{name: "observation-instance-restart", source: "observation_setup_lab_linux.go", before: "instance.InstanceID == binding.InstanceID", after: "false", test: "TestLabObservationFormatOwnedSetup", assertion: "same instance reused across restart"},
		{name: "observation-native-lock", source: "observation_lab_linux.go", before: "source.store.Lock(ctx, 0)", after: "func() (func(), error) { return func() {}, nil }()", test: "TestLabObservationBounds/lock", assertion: "native observation bound bypassed"},
		{name: "observation-native-hold", source: "observation_lab_linux.go", before: "source.policy.Limits.LockMS < 25", after: "false", test: "TestLabObservationBounds/native-hold", assertion: "native observation bound bypassed"},
		{name: "observation-clock", source: "observation_lab_linux.go", before: "now < acquired", after: "false", test: "TestLabObservationBounds/clock", assertion: "native observation bound bypassed"},
		{name: "observation-sticky-persistence", source: "observation_lab_linux.go", before: "source.failed = true", after: "source.failed = false", test: "TestLabObservationCounterPersistence", assertion: "uncertain persistence did not close admission"},
		{name: "observation-frame-size", source: "observation_server_lab_linux.go", before: "length > 4096 || used != 4+length", after: "length > 4095 || used != 4+length", test: "TestLabObservationFrameLimit", assertion: "at-limit frame refused"},
		{name: "observation-store-proof", source: "observation_lab_linux.go", before: "generation != binding.StoreGeneration {\n\t\treturn binding", after: "generation != generation {\n\t\treturn binding", test: "TestLabObservationEvidenceRefusals/store-proof", assertion: "bad native evidence produced a success frame"},
		{name: "observation-fresh-store", source: "observation_setup_lab_linux.go", before: "len(state.Effects) != 0", after: "false", test: "TestLabObservationFreshStore", assertion: "existing native store adopted by lab"},
	}
	for _, plant := range plants {
		plant.tags = "manager_lab"
		plant.control = "TestLabObservationRequestCatalogue"
		if plant.name == "observation-request-closure" || plant.name == "observation-request-literal" || plant.name == "observation-request-native-id" {
			plant.control = "TestLabObservationNativeJoin"
		}
		plant.pattern = "^(" + strings.Split(plant.test, "/")[0] + "|" + plant.control + ")$"
		test.Run(plant.name, func(test *testing.T) { assertMappingProfilePlant(test, plant) })
	}
}
