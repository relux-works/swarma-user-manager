//go:build linux

package linuxbackend

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-user-manager/internal/linuxos"
	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

type memoryDir struct {
	id               linuxos.FSIdentity
	children         map[string]*memoryDir
	host             *hostFixture
	writes, verifies *int
	next             *uint64
	fail             string
}

func (d *memoryDir) Close() error { return nil }
func (d *memoryDir) Observe(_ context.Context, name string, _ int64) (linuxos.FSIdentity, error) {
	if v, ok := d.children[name]; ok {
		return v.id, nil
	}
	return linuxos.FSIdentity{}, unix.ENOENT
}
func (d *memoryDir) OpenDirectory(name string) (directory, error) {
	v, ok := d.children[name]
	if !ok {
		return nil, unix.ENOENT
	}
	return v, nil
}
func (d *memoryDir) CreateStage(_ context.Context, key string) (stageHandle, error) {
	name, _, _ := linuxos.EffectNames(key)
	if _, ok := d.children[name]; ok {
		return nil, unix.EEXIST
	}
	*d.next++
	v := &memoryDir{id: linuxos.FSIdentity{Device: 1, Inode: *d.next, Type: "directory", UID: 0, GID: 0, Mode: 0700, Nlink: 2}, children: map[string]*memoryDir{}, host: d.host, writes: d.writes, verifies: d.verifies, next: d.next}
	d.children[name] = v
	d.id.Nlink++
	*d.writes++
	return &memoryStage{parent: d, node: v, leaf: name}, nil
}
func (d *memoryDir) Verify(context.Context, linuxos.Manifest, linuxos.Limits) (map[string][32]byte, error) {
	*d.verifies++
	return map[string][32]byte{}, nil
}
func (d *memoryDir) PrepareDeletion(_ context.Context, name string, _ linuxos.Limits, _ int) ([]linuxos.DeletionEntry, error) {
	v, ok := d.children[name]
	if !ok {
		return []linuxos.DeletionEntry{}, nil
	}
	return []linuxos.DeletionEntry{{Path: "", Parent: d.id, Object: v.id}}, nil
}
func (d *memoryDir) DeleteEntries(_ context.Context, name string, r linuxos.FSIdentity, v []linuxos.DeletionEntry, _ linuxos.Limits) (linuxos.Deletion, error) {
	obj, ok := d.children[name]
	if !ok || obj.id != r || len(v) != 1 || v[0].Parent != d.id || v[0].Object != r {
		return linuxos.Deletion{}, errors.New("different exact batch")
	}
	delete(d.children, name)
	d.id.Nlink--
	*d.writes++
	return linuxos.Deletion{Visited: 1, Removed: 1, Done: true}, nil
}

type memoryStage struct {
	parent, node *memoryDir
	leaf, phase  string
	closed       bool
}

func (s *memoryStage) Close() error                 { s.closed = true; return nil }
func (s *memoryStage) Identity() linuxos.FSIdentity { return s.node.id }
func (s *memoryStage) Populate(_ context.Context, r linuxos.FSIdentity, _ linuxos.Manifest, _ linuxos.Limits) (map[string]linuxos.FSIdentity, error) {
	if r != s.node.id || s.closed {
		return nil, errors.New("wrong live receipt")
	}
	*s.node.writes++
	s.node.id.GID = 24000
	s.node.id.Mode = 0750
	out := map[string]linuxos.FSIdentity{}
	for n, p := range s.node.host.paths {
		o := s.node.id
		if p != "" {
			o.Inode += uint64(n + 100)
		}
		out[p] = o
	}
	return out, nil
}
func (s *memoryStage) move(to directory, name string, r linuxos.FSIdentity, phase string) (linuxos.FSIdentity, error) {
	d := to.(*memoryDir)
	if s.closed || r != s.node.id {
		return linuxos.FSIdentity{}, errors.New("wrong live receipt")
	}
	if _, ok := d.children[name]; ok {
		return linuxos.FSIdentity{}, unix.EEXIST
	}
	delete(s.parent.children, s.leaf)
	s.parent.id.Nlink--
	d.children[name] = s.node
	d.id.Nlink++
	s.parent, s.leaf, s.phase = d, name, phase
	*s.node.writes++
	if d.fail == phase {
		return linuxos.FSIdentity{}, errors.New("post-rename sync failure")
	}
	return s.node.id, nil
}
func (s *memoryStage) Publish(_ context.Context, to directory, name string, r linuxos.FSIdentity) (linuxos.FSIdentity, error) {
	return s.move(to, name, r, "published")
}
func (s *memoryStage) Quarantine(_ context.Context, to directory, key string, r linuxos.FSIdentity) (linuxos.FSIdentity, error) {
	if s.phase != "published" {
		return linuxos.FSIdentity{}, errors.New("not published")
	}
	_, name, _ := linuxos.EffectNames(key)
	return s.move(to, name, r, "quarantined")
}
func memoryFilesystem(h *hostFixture) (func(context.Context, string) (*anchor, error), *memoryDir, *memoryDir, *int, *int) {
	writes, verifies := 0, 0
	next := uint64(50)
	parent := &memoryDir{children: map[string]*memoryDir{}}
	dirs := []*memoryDir{}
	for n := 0; n < 2; n++ {
		d := &memoryDir{id: linuxos.FSIdentity{Device: 1, Inode: uint64(n + 1), Type: "directory", UID: 0, GID: 0, Mode: 0700, Nlink: 2}, children: map[string]*memoryDir{}, host: h, writes: &writes, verifies: &verifies, next: &next}
		dirs = append(dirs, d)
	}
	parent.children["stages"] = dirs[0]
	parent.children["workers"] = dirs[1]
	open := func(_ context.Context, path string) (*anchor, error) {
		leaf := filepath.Base(path)
		d, ok := parent.children[leaf]
		if !ok {
			return nil, unix.ENOENT
		}
		return &anchor{parent: parent, dir: d, leaf: leaf, identity: fileObject(d.id)}, nil
	}
	return open, dirs[0], dirs[1], &writes, &verifies
}
func resolve(t manager.Task, a manager.Attempt, out manager.Completion) manager.Task {
	t.Records = add(a.Task.Records, "receipt", manager.Receipt{Key: a.Intent.Key, Attempt: a.Flight.Attempt, FlightHash: a.FlightHash, Outcome: out.Outcome, Objects: out.Objects, ManifestDigest: a.Intent.ManifestDigest})
	t.NextEffect.Ordinal++
	return t
}

// With primitive seams, home creation schedules exactly stage/create, populate
// and publish as separately durable writes. Publication keeps the ordered
// manifest correspondence; cleanup separately quarantines then deletes exact
// admitted entries. Real filesystem/root behavior is covered separately/pending.
func TestAdapterSplitHomeAndDeletionFlights(t *testing.T) {
	p, in := fixture()
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	b.reservations[in.Identity.Generation] = in
	open, stages, homes, writes, verifies := memoryFilesystem(h)
	b.open = open
	defer b.Close()
	current := task(in, p)
	current.Step = "home"
	for n, op := range []string{"stage_create", "managed_install", "home_publish"} {
		planned, e := b.Plan(context.Background(), current)
		if e != nil || planned.Complete || planned.Intent.Operation != op || *writes != n {
			t.Fatal(planned, e, *writes)
		}
		a := attempt(current, planned.Intent, p)
		out, e := b.Execute(context.Background(), a)
		if e != nil || out.Outcome != "applied" || !out.Stopped || *writes != n+1 {
			t.Fatal(out, e, *writes)
		}
		if op == "managed_install" {
			if len(out.Objects) != len(h.paths) {
				t.Fatal("path binding discarded")
			}
			var first manager.FileObject
			if json.Unmarshal(out.Objects[0], &first) != nil || first != fileObject(b.stageFor(in.Identity.Generation).handle.Identity()) {
				t.Fatal("root is not first manifest entry")
			}
		}
		current = resolve(current, a, out)
	}
	if planned, e := b.Plan(context.Background(), current); e != nil || !planned.Complete || *writes != 3 || *verifies == 0 || len(homes.children) != 1 || len(stages.children) != 0 {
		t.Fatal(planned, e, *writes, *verifies)
	}
	// Same lifetime, distinct cleanup actor; no numeric ownership join occurs.
	in.MayCreate = false
	in.Reservation.Phase = "cleanup"
	in.Reservation.Owner = "operator"
	in.Reservation.Request = manager.Request{V: 1, Op: "user.retire", ID: "retire"}
	in.Records = current.Records
	b.reservations[in.Identity.Generation] = in
	current = task(in, p)
	current.Step = "delete"
	for n, op := range []string{"home_quarantine", "delete_batch"} {
		planned, e := b.Plan(context.Background(), current)
		if e != nil || planned.Complete || planned.Intent.Operation != op || *writes != 3+n {
			t.Fatal(planned, e, *writes)
		}
		a := attempt(current, planned.Intent, p)
		out, e := b.Execute(context.Background(), a)
		if e != nil || out.Outcome != "applied" || out.Done != (op == "delete_batch") || *writes != 4+n {
			t.Fatal(out, e, *writes)
		}
		current = resolve(current, a, out)
	}
	if planned, e := b.Plan(context.Background(), current); e != nil || !planned.Complete || !planned.Done || len(homes.children)+len(stages.children) != 0 {
		t.Fatal(planned, e)
	}
}

// A post-rename failure remains unknown and poisons the live continuation;
// neither compensation nor a retry may adopt/repeat the moved home. Adjacent
// clean publication is exercised by TestAdapterSplitHomeAndDeletionFlights.
func TestAdapterPublicationErrorPreservesHold(t *testing.T) {
	p, in := fixture()
	h := newHost()
	b := NewWithEnvironment(p, h, nil)
	b.reservations[in.Identity.Generation] = in
	open, stages, homes, writes, _ := memoryFilesystem(h)
	b.open = open
	defer b.Close()
	homes.fail = "published"
	current := task(in, p)
	current.Step = "home"
	for _, op := range []string{"stage_create", "managed_install"} {
		planned, e := b.Plan(context.Background(), current)
		if e != nil || planned.Intent.Operation != op {
			t.Fatal(planned, e)
		}
		a := attempt(current, planned.Intent, p)
		out, e := b.Execute(context.Background(), a)
		if e != nil {
			t.Fatal(e)
		}
		current = resolve(current, a, out)
	}
	planned, e := b.Plan(context.Background(), current)
	if e != nil || planned.Intent.Operation != "home_publish" {
		t.Fatal(planned, e)
	}
	a := attempt(current, planned.Intent, p)
	out, e := b.Execute(context.Background(), a)
	if e == nil || out.Outcome != "unknown" || len(out.Objects) != 0 || !b.stageFor(in.Identity.Generation).poisoned || *writes != 3 || len(homes.children) != 1 || len(stages.children) != 0 {
		t.Fatal(out, e, *writes)
	}
	current = resolve(current, a, out)
	if planned, e = b.Plan(context.Background(), current); code(e) != "cleanup_pending" || planned.Complete || *writes != 3 || len(homes.children) != 1 {
		t.Fatal("moved object retried/adopted", planned, e, *writes)
	}
}
