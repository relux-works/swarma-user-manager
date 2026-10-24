//go:build linux

package linuxos

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

type round2Names struct {
	uid uint32
	err error
}

func (n round2Names) UID(context.Context, string) (uint32, error) { return n.uid, n.err }

// The returned UID is not validated evidence when its lookup failed. A valid
// lookup of the same UID must still report the real spool once; system-cron
// provides the neighboring parser control for this public Names contract.
func TestRound2SchedulerDoesNotFabricateErrorUID(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	for _, kind := range []string{"cron", "system-cron"} {
		t.Run(kind, func(t *testing.T) {
			paths := []string{t.TempDir(), t.TempDir(), t.TempDir()}
			sources := []Spool{{fixtureDir(t, paths[0]), "cron"}, {fixtureDir(t, paths[1]), "system-cron"}, {fixtureDir(t, paths[2]), "at"}}
			index := 0
			contents := "* * * * * true\n"
			if kind == "system-cron" {
				index = 1
				contents = "* * * * * fixture true\n"
			}
			if e := os.WriteFile(filepath.Join(paths[index], "fixture"), []byte(contents), 0600); e != nil {
				t.Fatal(e)
			}
			positive := Scheduler(context.Background(), uid, sources, round2Names{uid: uid}, testLimits())
			if positive.Verdict != Dirty || positive.Err != nil || len(positive.Objects) != 1 {
				t.Fatalf("valid lookup control: verdict=%s objects=%d err=%v", positive.Verdict, len(positive.Objects), positive.Err)
			}
			partial := Scheduler(context.Background(), uid, sources, round2Names{uid: uid, err: unix.EACCES}, testLimits())
			if partial.Verdict != Unknown || !errors.Is(partial.Err, unix.EACCES) {
				t.Fatal("failed lookup not Unknown/EACCES")
			}
			if len(partial.Objects) != 0 {
				t.Errorf("failed UID lookup fabricated %d validated ownership observations; expected zero", len(partial.Objects))
			}
		})
	}
}

// Retaining fstat evidence across a depth refusal must neither invent unseen
// descendants nor duplicate the already-recorded directory on the next scan.
func TestRound2FilesPartialIdentitySet(t *testing.T) {
	path := t.TempDir()
	root := fixtureDir(t, path)
	if e := os.MkdirAll(filepath.Join(path, "a", "b"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "a", "b", "leaf"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	l := testLimits()
	l.Depth = 1
	r := Files(context.Background(), uint32(os.Getuid()), []*Dir{root}, l)
	if r.Verdict != Unknown || errorCode(r.Err) != "inventory_limit" {
		t.Fatal("depth boundary not Unknown/limit")
	}
	want := map[string]bool{"0": true, "0/a": true, "0/a/b": true}
	for _, o := range r.Objects {
		if !want[o.Name] {
			t.Fatalf("fabricated or duplicate object name: %s", o.Name)
		}
		delete(want, o.Name)
	}
	if len(want) != 0 {
		t.Fatalf("lost %d observed identities", len(want))
	}
	r = Files(context.Background(), uint32(os.Getuid()), []*Dir{root}, testLimits())
	if r.Verdict != Dirty || len(r.Objects) != 4 || r.Err != nil {
		t.Fatalf("complete control: verdict=%s count=%d err=%v", r.Verdict, len(r.Objects), r.Err)
	}
}

// The exported Systemd entry retains its validated unit observation when a
// later configured source is missing; this fails before any host admin query.
func TestRound2SystemdPublicPartialSource(t *testing.T) {
	uid := uint32(os.Getuid()) + 100000
	a, b := t.TempDir(), t.TempDir()
	unit, linger := fixtureDir(t, a), fixtureDir(t, b)
	if e := os.WriteFile(filepath.Join(a, "known.timer"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	r := Systemd(context.Background(), uid, SystemdSources{Units: []*Dir{unit}, Runtime: []*Dir{nil}, Linger: linger, User: "fixture"}, testLimits())
	if r.Verdict != Unknown || errorCode(r.Err) != "inventory_unknown" || len(r.Objects) != 1 || r.Objects[0].Name != "units:known.timer" || r.Objects[0].UID != uid {
		t.Fatal("public wrapper lost validated partial source observation")
	}
}
