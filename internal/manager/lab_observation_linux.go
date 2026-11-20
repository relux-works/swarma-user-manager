//go:build linux && manager_lab

package manager

func LabObservationState(raw []byte) (State, error) {
	return decodeCensusEffects(raw)
}
