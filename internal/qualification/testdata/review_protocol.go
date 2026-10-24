package qualification

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

type collisionStore struct {
	linuxos.QualificationFile
	path      string
	collision bool
	collided  bool
}

func (s *collisionStore) Publish(ctx context.Context, b []byte) error {
	if s.collision {
		// Model a different writer arriving after Issue withdrew the prior record.
		if e := os.WriteFile(s.path, []byte("foreign-protected-record"), 0600); e != nil {
			return e
		}
	}
	e := s.QualificationFile.Publish(ctx, b)
	s.collided = errors.Is(e, unix.EEXIST)
	return e
}

// The public issuer must preserve a foreign final record after the real no-replace
// publisher returns EEXIST. Only the directory ownership is fixture-mapped; real
// Publish, Withdraw, Read and Protocol.Issue execute unchanged candidate code.
func TestReviewQualificationForeignRecordAfterPublishFailure(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "control"
		if collision {
			name = "foreign-final-collision"
		}
		t.Run(name, func(t *testing.T) {
			s, p, _, _, _ := setup()
			dir := t.TempDir()
			if e := os.Chmod(dir, 0700); e != nil {
				t.Fatal(e)
			}
			d, e := linuxos.ReviewFixtureAnchor(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			if e := (linuxos.QualificationFile{Directory: d}).Withdraw(context.Background()); e != nil {
				t.Fatal("fixture record prerequisite", e)
			}
			path := filepath.Join(dir, "record.json")
			store := &collisionStore{QualificationFile: linuxos.QualificationFile{Directory: d}, path: path, collision: collision}
			s.Storage = store
			_, e = s.Issue(context.Background(), p, false)
			b, re := os.ReadFile(path)
			if !collision {
				if e != nil || re != nil || len(b) == 0 {
					t.Fatal("positive issuance failed", e, re)
				}
				return
			}
			if e != ErrRequired || !store.collided {
				t.Fatal("wrong refusal or collision not reached", e, store.collided)
			}
			if re != nil || string(b) != "foreign-protected-record" {
				t.Fatalf("issuer deleted foreign record after real EEXIST publication: read=%v retained=%q", re, b)
			}
		})
	}
}
