//go:build linux

package linuxbackend

import (
	"context"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
)

// These private seams preserve the primitive's live capabilities. Production
// constructs only the concrete wrappers below; tests can exercise scheduling
// without root or forging a linuxos OwnedStage.
type directory interface {
	Close() error
	Observe(context.Context, string, int64) (linuxos.FSIdentity, error)
	OpenDirectory(string) (directory, error)
	CreateStage(context.Context, string) (stageHandle, error)
	Verify(context.Context, linuxos.Manifest, linuxos.Limits) (map[string][32]byte, error)
	PrepareDeletion(context.Context, string, linuxos.Limits, int) ([]linuxos.DeletionEntry, error)
	DeleteEntries(context.Context, string, linuxos.FSIdentity, []linuxos.DeletionEntry, linuxos.Limits) (linuxos.Deletion, error)
}
type stageHandle interface {
	Close() error
	Identity() linuxos.FSIdentity
	Populate(context.Context, linuxos.FSIdentity, linuxos.Manifest, linuxos.Limits) (map[string]linuxos.FSIdentity, error)
	Publish(context.Context, directory, string, linuxos.FSIdentity) (linuxos.FSIdentity, error)
	Quarantine(context.Context, directory, string, linuxos.FSIdentity) (linuxos.FSIdentity, error)
}
type linuxDirectory struct{ d *linuxos.Dir }

func (d *linuxDirectory) Close() error { return d.d.Close() }
func (d *linuxDirectory) Observe(c context.Context, s string, n int64) (linuxos.FSIdentity, error) {
	return d.d.Observe(c, s, n)
}
func (d *linuxDirectory) OpenDirectory(s string) (directory, error) {
	v, e := d.d.OpenDirectory(s)
	if e != nil {
		return nil, e
	}
	return &linuxDirectory{v}, nil
}
func (d *linuxDirectory) CreateStage(c context.Context, key string) (stageHandle, error) {
	v, e := d.d.CreateStage(c, key)
	if v == nil {
		return nil, e
	}
	return &linuxStage{v}, e
}
func (d *linuxDirectory) Verify(c context.Context, m linuxos.Manifest, l linuxos.Limits) (map[string][32]byte, error) {
	return d.d.Verify(c, m, l)
}
func (d *linuxDirectory) PrepareDeletion(c context.Context, s string, l linuxos.Limits, n int) ([]linuxos.DeletionEntry, error) {
	return d.d.PrepareDeletion(c, s, l, n)
}
func (d *linuxDirectory) DeleteEntries(c context.Context, s string, r linuxos.FSIdentity, v []linuxos.DeletionEntry, l linuxos.Limits) (linuxos.Deletion, error) {
	return d.d.DeleteEntries(c, s, r, v, l)
}

type linuxStage struct{ s *linuxos.OwnedStage }

func (s *linuxStage) Close() error                 { return s.s.Close() }
func (s *linuxStage) Identity() linuxos.FSIdentity { return s.s.Identity() }
func (s *linuxStage) Populate(c context.Context, r linuxos.FSIdentity, m linuxos.Manifest, l linuxos.Limits) (map[string]linuxos.FSIdentity, error) {
	return s.s.Populate(c, r, m, l)
}
func (s *linuxStage) Publish(c context.Context, to directory, name string, r linuxos.FSIdentity) (linuxos.FSIdentity, error) {
	d, ok := to.(*linuxDirectory)
	if !ok {
		return linuxos.FSIdentity{}, refuse("qualification_required")
	}
	return s.s.Publish(c, d.d, name, r)
}
func (s *linuxStage) Quarantine(c context.Context, to directory, key string, r linuxos.FSIdentity) (linuxos.FSIdentity, error) {
	d, ok := to.(*linuxDirectory)
	if !ok {
		return linuxos.FSIdentity{}, refuse("qualification_required")
	}
	return s.s.Quarantine(c, d.d, key, r)
}
