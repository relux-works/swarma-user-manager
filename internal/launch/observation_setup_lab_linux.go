//go:build linux && manager_lab

package launch

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

type labObservationInstance struct {
	Format     string `json:"format"`
	Generation string `json:"generation"`
	InstanceID string `json:"instance_id"`
}

type labObservationStoreProof struct {
	Format     string `json:"format"`
	Generation string `json:"generation"`
}

func (store *Store) labStoreGeneration() (string, error) {
	raw, err := manager.ReadProtected(store.dir, "lab-observation-store.json", store.owner, 4096)
	var proof labObservationStoreProof
	if err != nil || manager.Strict(raw, &proof) != nil || proof.Format != "station-lab-observation-store/1" || !manager.ValidGeneration(proof.Generation) {
		return "", fail("effect_evidence_unavailable")
	}
	return proof.Generation, nil
}

func ProvisionLabObservation(root, generation string) error {
	store, err := Open(root)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.provisionLabObservation(generation, manager.NativeJournal{Path: root + "/lib/user-manager/generations"})
}

func (store *Store) provisionLabObservation(generation string, journal manager.Journal) error {
	if !manager.ValidGeneration(generation) || journal == nil {
		return fail("qualification_required")
	}
	unlock, err := store.Lock(context.Background(), 0)
	if err != nil {
		return err
	}
	defer unlock()
	for _, name := range []string{"lab-observation-store.json", "lab-observation-binding.json", "lab-observation-counter.json", "lab-observation-instance.json"} {
		var status unix.Stat_t
		if err := unix.Fstatat(int(store.dir.Fd()), name, &status, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, os.ErrNotExist) {
			return fail("effect_evidence_unavailable")
		}
	}
	effects, err := store.Load()
	if err != nil || effects.Revision != 1 || len(effects.Launches) != 0 || len(effects.Stops) != 0 {
		return fail("effect_evidence_unavailable")
	}
	debits, err := store.Debits()
	if err != nil || len(debits) != 0 {
		return fail("effect_evidence_unavailable")
	}
	invalidations, err := store.Invalidations()
	if err != nil || len(invalidations) != 0 {
		return fail("effect_evidence_unavailable")
	}
	descriptor, err := unix.Openat(int(store.receipts.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(descriptor), "receipts")
	names, readErr := directory.Readdirnames(1)
	closeErr := directory.Close()
	if !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) != 0 {
		return fail("effect_evidence_unavailable")
	}
	raw, err := manager.ReadProtected(store.journal, "effects.json", store.owner, 8*1024*1024)
	if err != nil {
		return err
	}
	state, err := manager.LabObservationState(raw)
	if err != nil || state.Revision != 1 || len(state.Effects) != 0 || len(state.OSRecords) != 0 || state.Floor.Seq != 0 || state.Floor.Hash != genjournal.ZeroHash {
		return fail("effect_evidence_unavailable")
	}
	return journal.Checkpoint(context.Background(), state.Floor, func(view genjournal.View) error {
		if view.Tail.Seq != 0 || view.Tail.Hash != genjournal.ZeroHash || len(view.Rows) != 0 || len(view.History) != 0 {
			return fail("effect_evidence_unavailable")
		}
		for _, object := range []struct {
			name  string
			value any
		}{
			{"lab-observation-counter.json", labObservationCounter{labObservationCounterFormat, generation, 1}},
			{"lab-observation-instance.json", labObservationInstance{"station-lab-observation-instance/1", generation, ""}},
			{"lab-observation-store.json", labObservationStoreProof{"station-lab-observation-store/1", generation}},
		} {
			encoded, err := manager.ObjectBytes(object.value)
			if err != nil {
				return err
			}
			if err := manager.WriteProtected(store.dir, object.name, encoded, store.owner); err != nil {
				return err
			}
		}
		return nil
	})
}

func InstallLabObservationBinding(root string, binding LabObservationBinding) error {
	store, err := Open(root)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.installLabObservationBinding(binding)
}

func (store *Store) installLabObservationBinding(binding LabObservationBinding) error {
	if !binding.valid() {
		return fail("qualification_required")
	}
	unlock, err := store.Lock(context.Background(), 0)
	if err != nil {
		return err
	}
	defer unlock()
	generation, err := store.labStoreGeneration()
	if err != nil || generation != binding.StoreGeneration {
		return fail("effect_evidence_unavailable")
	}
	if _, err := store.labCounter(generation); err != nil {
		return err
	}
	if _, _, err := store.Account(binding.AccountGeneration); err != nil {
		return err
	}
	var status unix.Stat_t
	if err := unix.Fstatat(int(store.dir.Fd()), "lab-observation-binding.json", &status, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, os.ErrNotExist) {
		return fail("effect_evidence_unavailable")
	}
	encoded, err := manager.ObjectBytes(binding)
	if err != nil {
		return err
	}
	return manager.WriteProtected(store.dir, "lab-observation-binding.json", encoded, store.owner)
}

func (store *Store) labBeginObservation(binding LabObservationBinding) error {
	unlock, err := store.Lock(context.Background(), 0)
	if err != nil {
		return err
	}
	defer unlock()
	current, err := store.labBinding()
	if err != nil || current != binding {
		return fail("qualification_required")
	}
	if _, err := store.labCounter(binding.StoreGeneration); err != nil {
		return err
	}
	raw, err := manager.ReadProtected(store.dir, "lab-observation-instance.json", store.owner, 4096)
	var instance labObservationInstance
	if err != nil || manager.Strict(raw, &instance) != nil || instance.Format != "station-lab-observation-instance/1" || instance.Generation != binding.StoreGeneration || instance.InstanceID == binding.InstanceID || instance.InstanceID != "" && !manager.ValidGeneration(instance.InstanceID) {
		return fail("effect_evidence_unavailable")
	}
	instance.InstanceID = binding.InstanceID
	encoded, err := manager.ObjectBytes(instance)
	if err != nil {
		return err
	}
	return manager.WriteProtected(store.dir, "lab-observation-instance.json", encoded, store.owner)
}
