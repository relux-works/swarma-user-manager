package manager

import "errors"

var ErrRecoveryUnavailable = errors.New("manager recovery unavailable; retain hold and original funding")

// Production entry points have no authority producer. Matching IDs, UID 0,
// copied evidence or local storage visibility cannot open them.
func PrepareManagerRecovery() error { return ErrRecoveryUnavailable }
func PrepareManagerRelease() error  { return ErrRecoveryUnavailable }

// Normal finish requires the separately reviewed combined Q3 v2 lifetime API.
// In particular existing post-unlink Finish cannot prepare release before unlink.
func prepareManagerNormalRelease() error { return ErrRecoveryUnavailable }
