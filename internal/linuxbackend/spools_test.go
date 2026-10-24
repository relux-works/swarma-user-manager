//go:build linux

package linuxbackend

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/qualification"
)

// Closed deployment/1 spool entries require an explicit state and clean path;
// both reviewed states bind the manifest digest. Legacy strings cannot decode.
func TestQualificationSpoolSchema(t *testing.T) {
	for _, kind := range []string{"at", "cron"} {
		for _, mode := range []string{"present", "absent", "omitted", "unknown", "relative", "unclean", "root", "legacy", "extra"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				m := manifestFixture()
				p, _ := fixture()
				s := &m.Inventory.At
				if kind == "cron" {
					s = &m.Inventory.Cron
				}
				switch mode {
				case "present", "absent":
					s.State = mode
				case "omitted":
					s.State = ""
				case "unknown":
					s.State = "optional"
				case "relative":
					s.Path = "relative"
				case "unclean":
					s.Path = "/var/../spool/jobs"
				case "root":
					s.Path = "/"
				}
				raw, e := qualification.Canonical(m)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "legacy" || mode == "extra" {
					old, _ := qualification.Canonical(*s)
					value := []byte(`"/var/spool/cron/jobs"`)
					if mode == "extra" {
						value = append([]byte(`{"extra":true,`), old[1:]...)
					}
					raw = bytes.Replace(raw, old, value, 1)
				}
				p.BackendDigest = qualification.Hash(raw)
				var parsed DeploymentManifest
				e = qualification.DecodeClosed(raw, &parsed, 65536)
				if e == nil {
					e = parsed.validate(p)
				}
				if mode == "present" || mode == "absent" {
					if e != nil {
						t.Fatal("valid explicit state", e)
					}
				} else if e == nil {
					t.Fatal("invalid spool admitted")
				}
			})
		}
	}
}

// Production construction opens an absent spool's parent, not its missing
// leaf, and propagates failure with no partial source list. Present spools keep
// opening their path. Earlier sources use the real read-only / capability;
// no filesystem writes or host spool content reads occur in this routing test.
func TestQualificationSpoolRouting(t *testing.T) {
	for _, kind := range []string{"cron", "at"} {
		for _, state := range []string{"present", "absent"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				m := manifestFixture()
				target := &m.Inventory.At
				if kind == "cron" {
					target = &m.Inventory.Cron
				}
				target.State = state
				want := target.Path
				if state == "absent" {
					want = filepath.Dir(want)
				}
				marker := errors.New("owned routing witness")
				opened := []string{}
				dirs := []*linuxos.Dir{}
				defer func() {
					if e := closeDirs(dirs); e != nil {
						t.Error(e)
					}
				}()
				sources, e := inventorySpools(context.Background(), m.Inventory, func(path string) (*linuxos.Dir, error) {
					opened = append(opened, path)
					if path == want {
						return nil, marker
					}
					d, e := linuxos.OpenRoot("/")
					if e == nil {
						dirs = append(dirs, d)
					}
					return d, e
				})
				if !errors.Is(e, marker) || sources != nil || len(opened) == 0 || opened[len(opened)-1] != want {
					t.Fatal("spool routing or partial result", opened, sources, e)
				}
			})
		}
	}
}
