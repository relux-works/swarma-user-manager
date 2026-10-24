//go:build genjournal_testseam

package genjournal

import (
	"context"
	"os"
	"time"
)

// TestHandle uses a fixture's owner and anchor with the real journal primitives.
// It exists only with genjournal_testseam, which MUST NOT be used in production.
// It never changes the policy used by the package-level production functions.
type TestHandle struct {
	policy            policy
	readerHold        time.Duration
	invalidReaderHold bool
}

// TestOption configures a TestHandle only at construction. It exists only with
// genjournal_testseam and cannot configure package-level production functions.
type TestOption interface{ apply(*TestHandle) }

type readerHoldOption time.Duration

// WithReaderHold changes a fixture handle's real-clock reader window. Any
// nonpositive duration makes every method return journal_reader_hold without
// filesystem effects or callbacks, even if followed by a positive option.
// It does not change writer fence budgets or qualify production timing.
func WithReaderHold(d time.Duration) TestOption { return readerHoldOption(d) }

func (d readerHoldOption) apply(h *TestHandle) {
	if d <= 0 {
		h.invalidReaderHold = true
		return
	}
	h.readerHold = time.Duration(d)
}

type testReaderHoldKey struct{}

func readerHold(ctx context.Context) time.Duration {
	if d, ok := ctx.Value(testReaderHoldKey{}).(time.Duration); ok {
		return d
	}
	return ReaderHold
}

func (h *TestHandle) readerContext(ctx context.Context) (context.Context, error) {
	if h == nil || h.invalidReaderHold || h.readerHold <= 0 {
		return nil, refuse("journal_reader_hold")
	}
	return context.WithValue(ctx, testReaderHoldKey{}, h.readerHold), nil
}

// NewTestHandle constructs a handle for isolated consumer tests. The anchor must
// be an absolute protected directory containing the fixture paths. Ownership,
// modes, locks and deadlines are checked by the same primitives as production,
// using ownerUID instead of root. The default window remains ReaderHold; positive
// WithReaderHold options use the last duration. Nil options refuse just like an
// invalid duration. No files are initialized by this constructor.
func NewTestHandle(ownerUID uint32, anchor string, options ...TestOption) *TestHandle {
	h := &TestHandle{policy: policy{ownerUID, anchor}, readerHold: ReaderHold}
	for _, option := range options {
		if option == nil {
			h.invalidReaderHold = true
			continue
		}
		option.apply(h)
	}
	return h
}

// WithEvidence uses WithEvidence's consumer contract under the fixture policy.
func (h *TestHandle) WithEvidence(ctx context.Context, path string, floor Floor, commit func(View, time.Time) error) error {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return e
	}
	return withEvidence(ctx, path, floor, h.policy, commit)
}

// WithEvidenceAtBoundary observes the journal directly at the handle's anchor.
// The fixture must place its journal and lock files there. afterFirstCheck runs
// after the first pending-marker check and before shared gate acquisition; it
// may publish a marker to test the post-lock recheck. All verification, locking,
// deadline and consumer commit obligations remain those of WithEvidence.
func (h *TestHandle) WithEvidenceAtBoundary(ctx context.Context, floor Floor, afterFirstCheck func(), commit func(View, time.Time) error) error {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return e
	}
	return readWindowAtBoundary(ctx, h.policy.anchor, h.policy, afterFirstCheck, func(_ *directory, j *os.File, deadline time.Time) error {
		v, e := verifyUntil(j, floor, deadline)
		if e != nil {
			return e
		}
		return commitEvidence(v, deadline, commit)
	})
}

// WithActive checks the exact pair under the fixture policy.
func (h *TestHandle) WithActive(ctx context.Context, path string, floor Floor, uid int64, generation string, commit func(View, time.Time) error) error {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return e
	}
	return withActive(ctx, path, floor, uid, generation, h.policy, commit)
}

// Checkpoint persists bounded local effects and never admits a release.
func (h *TestHandle) Checkpoint(ctx context.Context, path string, floor Floor, fn func(View) error) error {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return e
	}
	return checkpoint(ctx, path, floor, h.policy, fn)
}

// Append applies the real durable service-writer transition to a fixture.
func (h *TestHandle) Append(ctx context.Context, path string, floor Floor, uid int64, generation, state, stamp string) (View, error) {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return View{}, e
	}
	return appendNative(ctx, path, floor, uid, generation, state, stamp, h.policy)
}

// Inspect is an offline diagnostic under the fixture policy, never admission.
func (h *TestHandle) Inspect(ctx context.Context, path string, floor Floor) (View, error) {
	ctx, e := h.readerContext(ctx)
	if e != nil {
		return View{}, e
	}
	return inspect(ctx, path, floor, h.policy)
}
