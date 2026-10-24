//go:build linux

package linuxbackend

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// The caller owns every descriptor returned by open, including absent parents.
// Initial/boot qualification and every inventory use the same state checks.
func inventorySpools(ctx context.Context, i InventoryProfile, open func(string) (*linuxos.Dir, error)) ([]linuxos.Spool, error) {
	out := []linuxos.Spool{}
	for _, v := range []struct {
		profile SpoolProfile
		kind    string
	}{
		{i.Cron, "cron"}, {SpoolProfile{State: "present", Path: i.SystemCron}, "system-cron"}, {i.At, "at"},
	} {
		p := v.profile
		if !absolute(p.Path) || p.Path == "/" || p.State != "present" && p.State != "absent" {
			return nil, qualification.ErrRequired
		}
		path := p.Path
		if p.State == "absent" {
			path = filepath.Dir(path)
		}
		d, e := open(path)
		if e != nil {
			return nil, e
		}
		s := linuxos.Spool{Kind: v.kind}
		if p.State == "present" {
			s.Root = d
		} else {
			s.Absent = &linuxos.ProtectedArtifact{Directory: d, Name: filepath.Base(p.Path), Path: p.Path}
		}
		if e = s.Check(ctx); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, nil
}

func checkInventorySpools(ctx context.Context, i InventoryProfile) (err error) {
	dirs := []*linuxos.Dir{}
	defer func() { err = errors.Join(err, closeDirs(dirs)) }()
	_, err = inventorySpools(ctx, i, func(path string) (*linuxos.Dir, error) {
		d, e := linuxos.OpenRoot(path)
		if e == nil {
			dirs = append(dirs, d)
		}
		return d, e
	})
	return err
}
