//go:build !genjournal_testseam

package genjournal

import (
	"context"
	"time"
)

// A production build always uses the protocol constant. Only the explicitly
// tagged fixture build can select a different per-handle reader duration.
func readerHold(context.Context) time.Duration { return ReaderHold }
