//go:build linux

package linuxos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A qualified missing cron/at leaf counts as covered only while ENOENT is
// re-proved under the protected existing parent. Any later object is unknown,
// including links and FIFOs; present jobs remain visible rather than ignored.
func TestQualificationSpoolState(t *testing.T) {
	for _, kind := range []string{"at", "cron"} {
		for _, mode := range []string{"absent-control", "appears-directory", "appears-file", "appears-link", "appears-fifo", "parent-writable", "ambiguous", "missing-parent", "system-cron-absent", "present-scanned"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				uid := uint32(os.Getuid()) + 100000
				roots := []string{t.TempDir(), t.TempDir(), t.TempDir()}
				sources := []Spool{{Root: fixtureDir(t, roots[0]), Kind: "cron"}, {Root: fixtureDir(t, roots[1]), Kind: "system-cron"}, {Root: fixtureDir(t, roots[2]), Kind: "at"}}
				index := 2
				if kind == "cron" {
					index = 0
				}
				parentPath := t.TempDir()
				parent := fixtureDir(t, parentPath)
				path := filepath.Join(parentPath, "jobs")
				absent := &ProtectedArtifact{Directory: parent, Name: "jobs", Path: path}
				sources[index] = Spool{Kind: kind, Absent: absent}
				scan := func() Result {
					return Scheduler(context.Background(), uid, sources, namesFixture{"fixture": uid}, testLimits())
				}
				if r := scan(); r.Verdict != Clean || r.Err != nil {
					t.Fatal("absent positive control", r)
				}
				switch mode {
				case "absent-control":
					return
				case "appears-directory":
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
				case "appears-file":
					if e := os.WriteFile(path, nil, 0600); e != nil {
						t.Fatal(e)
					}
				case "appears-link":
					if e := os.Symlink("missing", path); e != nil {
						t.Fatal(e)
					}
				case "appears-fifo":
					if e := unix.Mkfifo(path, 0600); e != nil {
						t.Fatal(e)
					}
				case "parent-writable":
					if e := os.Chmod(parentPath, 0777); e != nil {
						t.Fatal(e)
					}
				case "ambiguous":
					sources[index].Root = parent
				case "missing-parent":
					sources[index].Absent = &ProtectedArtifact{Name: "jobs", Path: path}
				case "system-cron-absent":
					sources[1] = Spool{Kind: "system-cron", Absent: absent}
				case "present-scanned":
					if e := os.Mkdir(path, 0700); e != nil {
						t.Fatal(e)
					}
					root := fixtureDir(t, path)
					if e := os.Chmod(path, 01730); e != nil {
						t.Fatal(e)
					}
					sources[index] = Spool{Root: root, Kind: kind}
					name, text := "fixture", "* * * * * true\n"
					if kind == "at" {
						name = "job"
						text = fmt.Sprintf("#!/bin/sh\n# atrun uid=%d gid=%d\n", uid, uid)
					}
					if e := os.WriteFile(filepath.Join(path, name), []byte(text), 0600); e != nil {
						t.Fatal(e)
					}
					r := scan()
					if r.Verdict != Dirty || r.Err != nil || len(r.Objects) != 1 || r.Objects[0].UID != uid || r.Objects[0].Name != kind+":"+name {
						t.Fatal("present job missed", r)
					}
					return
				}
				r := scan()
				if r.Verdict != Unknown || r.Err == nil {
					t.Fatal("unsafe or appeared spool accepted", r)
				}
				if mode == "appears-directory" || mode == "appears-file" || mode == "appears-link" || mode == "appears-fifo" {
					var e *Error
					if !errors.As(r.Err, &e) || e.Code != "inventory_unknown" || e.Operation != "spool_appeared" {
						t.Fatal("wrong appearance refusal", r.Err)
					}
				}
			})
		}
	}
}
