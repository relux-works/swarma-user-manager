//go:build genjournal_testseam

package genjournal

import (
	"context"
	"time"
)

// TestHandle uses a fixture's owner and anchor with the real journal primitives.
// It exists only with genjournal_testseam, which MUST NOT be used in production.
// It never changes the policy used by the package-level production functions.
type TestHandle struct{ policy policy }

// NewTestHandle constructs a handle for isolated consumer tests. The anchor must
// be an absolute protected directory containing the fixture paths. Ownership,
// modes, locks and deadlines are checked by the same primitives as production,
// using ownerUID instead of root. No files are initialized by this constructor.
func NewTestHandle(ownerUID uint32, anchor string) *TestHandle {
	return &TestHandle{policy{ownerUID, anchor}}
}

// WithEvidence uses WithEvidence's consumer contract under the fixture policy.
func (h *TestHandle) WithEvidence(ctx context.Context, path string, floor Floor, commit func(View, time.Time) error) error {
	return withEvidence(ctx, path, floor, h.policy, commit)
}

// WithActive checks the exact pair under the fixture policy.
func (h *TestHandle) WithActive(ctx context.Context, path string, floor Floor, uid int64, generation string, commit func(View, time.Time) error) error {
	return withActive(ctx, path, floor, uid, generation, h.policy, commit)
}

// Checkpoint persists bounded local effects and never admits a release.
func (h *TestHandle) Checkpoint(ctx context.Context, path string, floor Floor, fn func(View) error) error {
	return checkpoint(ctx, path, floor, h.policy, fn)
}

// Append applies the real durable service-writer transition to a fixture.
func (h *TestHandle) Append(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string) (View, error) {
	return appendNative(ctx, path, floor, uid, generation, state, stamp, h.policy)
}

// Inspect is an offline diagnostic under the fixture policy, never admission.
func (h *TestHandle) Inspect(ctx context.Context, path string, floor Floor) (View, error) {
	return inspect(ctx, path, floor, h.policy)
}
