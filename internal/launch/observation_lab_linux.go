//go:build linux && manager_lab

package launch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"syscall"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

const (
	labObservationRequestFormat  = "swarma-broker-lab-observation-request/1"
	labObservationResponseFormat = "swarma-broker-lab-observation-response/1"
	labObservationBindingFormat  = "station-lab-observation-binding/1"
	labObservationCounterFormat  = "station-lab-observation-counter/1"
	labObservationMaxSequence    = int64(9007199254740991)
)

type LabObservationBinding struct {
	Format            string `json:"format"`
	DaemonUID         int64  `json:"daemon_uid"`
	DaemonGID         int64  `json:"daemon_gid"`
	Identity          string `json:"identity"`
	ExecutableSHA256  string `json:"executable_sha256"`
	InstanceID        string `json:"instance_id"`
	StoreGeneration   string `json:"store_generation"`
	Owner             string `json:"owner"`
	AccountGeneration string `json:"account_generation"`
}

func (binding LabObservationBinding) valid() bool {
	return binding.Format == labObservationBindingFormat && binding.DaemonUID > 0 && binding.DaemonUID < 4294967295 && binding.DaemonGID > 0 && binding.DaemonGID < 4294967295 && manager.ValidRequestID(binding.Identity) && manager.HashOK(binding.ExecutableSHA256) && manager.ValidGeneration(binding.InstanceID) && manager.ValidGeneration(binding.StoreGeneration) && manager.ValidRequestID(binding.Owner) && manager.ValidGeneration(binding.AccountGeneration)
}

type labObservationRequest struct {
	Format      string `json:"format"`
	OperationID string `json:"operation_id"`
	StartID     string `json:"start_id"`
}

func parseLabObservationRequest(raw []byte) (labObservationRequest, error) {
	var request labObservationRequest
	if len(raw) == 0 || len(raw) > 4096 || manager.Strict(raw, &request) != nil || request.Format != labObservationRequestFormat || !manager.ValidRequestID(request.OperationID) || !manager.ValidRequestID(request.StartID) {
		return request, fail("request_invalid")
	}
	return request, nil
}

type labObservationHead struct {
	Sequence int64  `json:"sequence"`
	SHA256   string `json:"sha256"`
}

type labObservationManager struct {
	UID              int64  `json:"uid"`
	Identity         string `json:"identity"`
	ExecutableSHA256 string `json:"executable_sha256"`
	InstanceID       string `json:"instance_id"`
	BootID           string `json:"boot_id"`
}

type labObservationStore struct {
	Generation        string             `json:"generation"`
	ManagerHead       labObservationHead `json:"manager_head"`
	EffectsRevision   int64              `json:"effects_revision"`
	EffectsSHA256     string             `json:"effects_sha256"`
	ReceiptsSHA256    string             `json:"receipts_sha256"`
	DebitsHead        labObservationHead `json:"debits_head"`
	InvalidationsHead labObservationHead `json:"invalidations_head"`
	GenerationCurrent bool               `json:"generation_current"`
}

type labObservationStart struct {
	OperationID   string `json:"operation_id"`
	StartID       string `json:"start_id"`
	Owner         string `json:"owner"`
	Generation    string `json:"generation"`
	Epoch         int64  `json:"epoch"`
	UID           int64  `json:"uid"`
	Executor      string `json:"executor"`
	PlanSHA256    string `json:"plan_sha256"`
	ProfileID     string `json:"profile_id"`
	ProfileSHA256 string `json:"profile_sha256"`
	Phase         string `json:"phase"`
}

type labObservationStop struct {
	OperationID string `json:"operation_id"`
	Generation  string `json:"generation"`
	StartID     string `json:"start_id"`
	Phase       string `json:"phase"`
}

type labObservationResponse struct {
	Format              string                `json:"format"`
	OperationID         string                `json:"operation_id"`
	StartID             string                `json:"start_id"`
	Manager             labObservationManager `json:"manager"`
	Store               labObservationStore   `json:"store"`
	Sequence            int64                 `json:"sequence"`
	SequenceGeneration  string                `json:"sequence_generation"`
	ObservedMonotonicMS int64                 `json:"observed_monotonic_ms"`
	Complete            bool                  `json:"complete"`
	Start               labObservationStart   `json:"start"`
	Receipts            []Receipt             `json:"receipts"`
	Debits              []Debit               `json:"debits"`
	Invalidations       []Invalidation        `json:"invalidations"`
	Stops               []labObservationStop  `json:"stops"`
}

type labObservationCounter struct {
	Format     string `json:"format"`
	Generation string `json:"generation"`
	Sequence   int64  `json:"sequence"`
}

type labNativeSnapshot struct {
	Manager       []byte
	Effects       []byte
	Debits        []byte
	Invalidations []byte
	Receipts      []byte
	ReceiptBytes  []byte
	View          genjournal.View
	Objects       map[string]labObjectIdentity
}

type labObjectIdentity struct {
	Device   uint64
	Inode    uint64
	Links    uint64
	Size     int64
	Mode     uint32
	Owner    uint32
	Group    uint32
	Modified unix.Timespec
	Changed  unix.Timespec
}

func labObject(directory *os.File, name string) (labObjectIdentity, error) {
	var status unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return labObjectIdentity{}, err
	}
	return labObjectIdentity{uint64(status.Dev), status.Ino, uint64(status.Nlink), status.Size, status.Mode, status.Uid, status.Gid, status.Mtim, status.Ctim}, nil
}

func labDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func labBootNanos() (int64, error) {
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &clock); err != nil {
		return 0, err
	}
	return clock.Sec*int64(time.Second) + clock.Nsec, nil
}

func (store *Store) labCurrentDirectories() error {
	current, err := open(store.root, store.owner, store.anchor)
	if err != nil {
		return err
	}
	defer current.Close()
	for _, pair := range [][2]*os.File{{store.journal, current.journal}, {store.dir, current.dir}, {store.receipts, current.receipts}} {
		previous, err := pair[0].Stat()
		if err != nil {
			return err
		}
		present, err := pair[1].Stat()
		if err != nil || !os.SameFile(previous, present) {
			return fail("effect_evidence_unavailable")
		}
	}
	return nil
}

func (store *Store) labBinding() (LabObservationBinding, error) {
	var binding LabObservationBinding
	raw, err := manager.ReadProtected(store.dir, "lab-observation-binding.json", store.owner, 4096)
	if err != nil || manager.Strict(raw, &binding) != nil || !binding.valid() {
		return binding, fail("qualification_required")
	}
	generation, err := store.labStoreGeneration()
	if err != nil || generation != binding.StoreGeneration {
		return binding, fail("qualification_required")
	}
	return binding, nil
}

func (store *Store) labCounter(generation string) (labObservationCounter, error) {
	var counter labObservationCounter
	raw, err := manager.ReadProtected(store.dir, "lab-observation-counter.json", store.owner, 4096)
	if err != nil || manager.Strict(raw, &counter) != nil || counter.Format != labObservationCounterFormat || counter.Generation != generation || counter.Sequence < 1 || counter.Sequence > labObservationMaxSequence {
		return counter, fail("effect_evidence_unavailable")
	}
	return counter, nil
}

func (store *Store) labSnapshot(generation string, view genjournal.View) (labNativeSnapshot, error) {
	var snapshot labNativeSnapshot
	if err := store.labCurrentDirectories(); err != nil {
		return snapshot, err
	}
	snapshot.Objects = map[string]labObjectIdentity{}
	for _, object := range []struct {
		label     string
		directory *os.File
		name      string
	}{{"manager", store.journal, "effects.json"}, {"lock", store.journal, "effects.lock"}, {"effects", store.dir, "effects.json"}, {"debits", store.dir, "debits"}, {"invalidations", store.dir, "invalidations"}, {"store-proof", store.dir, "lab-observation-store.json"}, {"binding", store.dir, "lab-observation-binding.json"}} {
		identity, err := labObject(object.directory, object.name)
		if err != nil {
			return snapshot, err
		}
		snapshot.Objects[object.label] = identity
	}
	var err error
	if snapshot.Manager, err = manager.ReadProtected(store.journal, "effects.json", store.owner, 8*1024*1024); err != nil {
		return snapshot, err
	}
	if _, err = manager.LabObservationState(snapshot.Manager); err != nil {
		return snapshot, err
	}
	if snapshot.Effects, err = manager.ReadProtected(store.dir, "effects.json", store.owner, MaxEffects); err != nil {
		return snapshot, err
	}
	if snapshot.Debits, err = manager.ReadProtected(store.dir, "debits", store.owner, MaxLedger); err != nil {
		return snapshot, err
	}
	if snapshot.Invalidations, err = manager.ReadProtected(store.dir, "invalidations", store.owner, MaxLedger); err != nil {
		return snapshot, err
	}
	receipts, err := store.Receipts(generation)
	if err != nil || len(receipts) > 256 {
		return snapshot, fail("effect_evidence_unavailable")
	}
	if snapshot.Receipts, err = manager.ObjectBytes(receipts); err != nil {
		return snapshot, err
	}
	snapshot.ReceiptBytes = []byte{}
	if len(receipts) > 0 {
		directory, err := generationDir(store, generation, false)
		if err != nil {
			return snapshot, err
		}
		defer directory.Close()
		identity, err := labObject(store.receipts, generation)
		if err != nil {
			return snapshot, err
		}
		snapshot.Objects["receipt-generation"] = identity
		for _, receipt := range receipts {
			identity, err := labObject(directory, receipt.ExecutionID+".json")
			if err != nil {
				return snapshot, err
			}
			snapshot.Objects["receipt-"+receipt.ExecutionID] = identity
			descriptor, err := syscall.Openat(int(directory.Fd()), receipt.ExecutionID+".json", syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
			if err != nil {
				return snapshot, err
			}
			file := os.NewFile(uintptr(descriptor), receipt.ExecutionID)
			_, checkErr := ownedRegular(file, store.owner, 0644)
			raw, readErr := io.ReadAll(io.LimitReader(file, MaxLine+1))
			closeErr := file.Close()
			var decoded Receipt
			if checkErr != nil || readErr != nil || closeErr != nil || len(raw) > MaxLine || manager.Strict(raw, &decoded) != nil || decoded != receipt {
				return snapshot, fail("effect_evidence_unavailable")
			}
			snapshot.ReceiptBytes = append(snapshot.ReceiptBytes, raw...)
		}
	}
	snapshot.View = view
	return snapshot, nil
}

func (store *Store) labCollect(request labObservationRequest, binding LabObservationBinding, view genjournal.View, boot string) (labObservationResponse, labNativeSnapshot, error) {
	response := labObservationResponse{Format: labObservationResponseFormat, OperationID: request.OperationID, StartID: request.StartID, Complete: true, SequenceGeneration: binding.StoreGeneration, Receipts: []Receipt{}, Debits: []Debit{}, Invalidations: []Invalidation{}, Stops: []labObservationStop{}}
	snapshot, err := store.labSnapshot(binding.AccountGeneration, view)
	if err != nil {
		return response, snapshot, err
	}
	effects, err := store.Load()
	if err != nil {
		return response, snapshot, err
	}
	var selected *LaunchEffect
	for index := range effects.Launches {
		effect := &effects.Launches[index]
		if effect.RequestID == request.OperationID && effect.ExecutionID == request.StartID {
			if selected != nil || effect.Owner != binding.Owner || effect.Generation != binding.AccountGeneration {
				return response, snapshot, fail("effect_evidence_unavailable")
			}
			selected = effect
		}
	}
	if selected == nil {
		return response, snapshot, fail("effect_evidence_unavailable")
	}
	start := *selected
	if start.UID == binding.DaemonUID {
		return response, snapshot, fail("qualification_required")
	}
	account, _, err := store.Account(start.Generation)
	if err != nil {
		return response, snapshot, err
	}
	row, found := view.Generation(start.Generation)
	current := found && row.UID == start.UID && row.State == "active" && view.Active(start.UID, start.Generation) == nil && account.UID == start.UID && account.GID == start.UID && account.Generation == start.Generation
	latest := false
	for _, candidate := range view.Rows {
		if candidate.UID == start.UID && candidate.Generation == start.Generation {
			latest = true
		}
	}
	current = current && latest
	debits, err := DecodeDebits(snapshot.Debits)
	if err != nil {
		return response, snapshot, err
	}
	invalidations, err := DecodeInvalidations(snapshot.Invalidations)
	if err != nil {
		return response, snapshot, err
	}
	var receipts []Receipt
	if manager.Strict(snapshot.Receipts, &receipts) != nil {
		return response, snapshot, fail("effect_evidence_unavailable")
	}
	for _, receipt := range receipts {
		if receipt.ExecutionID == start.ExecutionID {
			response.Receipts = append(response.Receipts, receipt)
		}
	}
	for _, debit := range debits {
		if debit.Generation == start.Generation && debit.ExecutionID == start.ExecutionID {
			response.Debits = append(response.Debits, debit)
		}
	}
	for _, invalidation := range invalidations {
		if invalidation.Generation == start.Generation && invalidation.ExecutionID == start.ExecutionID {
			response.Invalidations = append(response.Invalidations, invalidation)
		}
	}
	for _, stop := range effects.Stops {
		if stop.Args.Generation == start.Generation && stop.Args.ExecutionID == start.ExecutionID {
			response.Stops = append(response.Stops, labObservationStop{stop.RequestID, stop.Args.Generation, stop.Args.ExecutionID, stop.Phase})
		}
	}
	if len(response.Receipts) > 1 || len(response.Debits) > 1 {
		return response, snapshot, fail("effect_evidence_unavailable")
	}
	if len(response.Debits) == 1 && len(response.Receipts) == 0 {
		return response, snapshot, fail("effect_evidence_unavailable")
	}
	for _, receipt := range response.Receipts {
		if receipt.Epoch != start.Epoch || receipt.BootID != boot {
			return response, snapshot, fail("effect_evidence_unavailable")
		}
	}
	if len(response.Receipts) == 1 && len(response.Debits) == 1 {
		receipt, debit := response.Receipts[0], response.Debits[0]
		if receipt.Epoch != debit.Epoch || receipt.Epoch != start.Epoch || receipt.PID != debit.PID || receipt.StartTime != debit.StartTime || receipt.BootID != debit.BootID || receipt.BootID != boot {
			return response, snapshot, fail("effect_evidence_unavailable")
		}
	}
	seen := map[Invalidation]bool{}
	for _, invalidation := range response.Invalidations {
		if seen[invalidation] || invalidation.BootID != boot {
			return response, snapshot, fail("effect_evidence_unavailable")
		}
		seen[invalidation] = true
	}
	response.Manager = labObservationManager{0, binding.Identity, "sha256:" + binding.ExecutableSHA256, binding.InstanceID, boot}
	response.Store = labObservationStore{binding.StoreGeneration, labObservationHead{view.Tail.Seq, "sha256:" + view.Tail.Hash}, effects.Revision, labDigest(snapshot.Effects), labDigest(snapshot.ReceiptBytes), labObservationHead{int64(len(debits)), labDigest(snapshot.Debits)}, labObservationHead{int64(len(invalidations)), labDigest(snapshot.Invalidations)}, current}
	response.Start = labObservationStart{start.RequestID, start.ExecutionID, start.Owner, start.Generation, start.Epoch, start.UID, start.Executor, "sha256:" + start.PlanDigest, start.ProfileID, "sha256:" + start.ProfileDigest, start.Phase}
	if err := response.valid(); err != nil {
		return response, snapshot, err
	}
	return response, snapshot, nil
}

func (response labObservationResponse) valid() error {
	if response.Start.UID < 1 || response.Start.UID >= 4294967295 || response.Store.EffectsRevision < 1 || response.Store.EffectsRevision > labObservationMaxSequence || len(response.Receipts) > 256 || len(response.Debits) > 256 || len(response.Invalidations) > 256 || len(response.Stops) > 256 {
		return fail("effect_evidence_unavailable")
	}
	for _, receipt := range response.Receipts {
		if receipt.PID > 4194304 || receipt.SessionID > 4194304 || receipt.StartTime > labObservationMaxSequence {
			return fail("effect_evidence_unavailable")
		}
	}
	for _, debit := range response.Debits {
		if debit.PID > 4194304 || debit.StartTime > labObservationMaxSequence {
			return fail("effect_evidence_unavailable")
		}
	}
	return nil
}

type labObservationSource struct {
	store        *Store
	journal      manager.Journal
	policy       manager.Policy
	binding      LabObservationBinding
	boot         string
	lastSequence int64
	failed       bool
	now          func() (int64, error)
}

func (source *labObservationSource) observe(ctx context.Context, raw []byte, deadline int64) ([]byte, error) {
	request, err := parseLabObservationRequest(raw)
	if err != nil {
		return nil, err
	}
	if source.failed || source.policy.Limits.LockMS <= 0 {
		return nil, fail("qualification_required")
	}
	acquired, err := source.now()
	if err != nil {
		return nil, err
	}
	lockObject, err := labObject(source.store.journal, "effects.lock")
	if err != nil {
		return nil, err
	}
	unlock, err := source.store.Lock(ctx, 0)
	if err != nil {
		return nil, err
	}
	defer unlock()
	currentLock, err := labObject(source.store.journal, "effects.lock")
	if err != nil || currentLock != lockObject {
		return nil, fail("effect_evidence_unavailable")
	}
	limit := int64(25 * time.Millisecond)
	if source.policy.Limits.LockMS < 25 {
		limit = source.policy.Limits.LockMS * int64(time.Millisecond)
	}
	check := func() error {
		now, err := source.now()
		if err != nil || now < acquired || now >= deadline || now-acquired >= limit || ctx.Err() != nil {
			return fail("target_busy")
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	binding, err := source.store.labBinding()
	if err != nil || binding != source.binding {
		return nil, fail("qualification_required")
	}
	counter, err := source.store.labCounter(binding.StoreGeneration)
	if err != nil || counter.Sequence < source.lastSequence || counter.Sequence == labObservationMaxSequence {
		return nil, fail("effect_evidence_unavailable")
	}
	_, floor, err := source.store.Account(binding.AccountGeneration)
	if err != nil {
		return nil, err
	}
	var response labObservationResponse
	err = source.journal.Checkpoint(ctx, floor, func(view genjournal.View) error {
		var before labNativeSnapshot
		var err error
		response, before, err = source.store.labCollect(request, binding, view, source.boot)
		if err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		counter.Sequence++
		encoded, err := manager.ObjectBytes(counter)
		if err != nil {
			return err
		}
		source.failed = true
		if err := manager.WriteProtected(source.store.dir, "lab-observation-counter.json", encoded, source.store.owner); err != nil {
			return err
		}
		stored, err := source.store.labCounter(binding.StoreGeneration)
		if err != nil || stored != counter {
			return fail("effect_evidence_unavailable")
		}
		after, err := source.store.labSnapshot(binding.AccountGeneration, view)
		currentBinding, bindingErr := source.store.labBinding()
		if err != nil || bindingErr != nil || currentBinding != binding || before.Objects["lock"] != lockObject || after.Objects["lock"] != lockObject || !reflect.DeepEqual(before, after) {
			return fail("effect_evidence_unavailable")
		}
		source.lastSequence = counter.Sequence
		response.Sequence = counter.Sequence
		now, err := source.now()
		if err != nil {
			return err
		}
		response.ObservedMonotonicMS = now / int64(time.Millisecond)
		for _, debit := range response.Debits {
			if debit.CommittedMS > response.ObservedMonotonicMS {
				return fail("effect_evidence_unavailable")
			}
		}
		return check()
	})
	if err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	encoded, err := manager.ObjectBytes(response)
	if err != nil || len(encoded) > 65536 {
		return nil, fail("effect_evidence_unavailable")
	}
	if err := check(); err != nil {
		return nil, err
	}
	source.failed = false
	return encoded, nil
}

func labReadExecutable() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
