package genjournal

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const capacityUID = int64(4294967294)
const capacityToken = "ffffffffffffffffffffffffffffffff"

// sizedCapacityHistory fills a valid diagnostic history with one requested live row
// and removed filler incarnations. UID widths, not padding or invalid bytes, fill the ceiling.
func sizedCapacityHistory(t *testing.T, size int, state string) []byte {
	t.Helper()
	records := []Record{}
	add := func(uid int64, gen, state string) {
		records = append(records, Record{int64(len(records) + 1), ZeroHash, uid, gen, state, "operator-manual", "2026-10-01T00:00:00Z"})
	}
	add(capacityUID, capacityToken, "creating")
	if state != "creating" {
		add(capacityUID, capacityToken, "active")
	}
	if state == "retiring" || state == "removed" {
		add(capacityUID, capacityToken, "retiring")
	}
	if state == "removed" {
		add(capacityUID, capacityToken, "removed")
	}
	length := func(r Record) int {
		b, e := Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		return len(b)
	}
	total := 0
	for _, r := range records {
		total += length(r)
	}
	firstFiller := len(records)
	for i := 1; ; i++ {
		gen := fmt.Sprintf("%032x", i)
		add(1, gen, "creating")
		add(1, gen, "removed")
		n := len(records)
		extra := length(records[n-2]) + length(records[n-1])
		if total+extra > size {
			records = records[:n-2]
			break
		}
		total += extra
	}
	gap := size - total
	if gap%2 == 1 {
		records[firstFiller].Writer = "user-manager"
		gap += 3
	}
	for i := firstFiller; i < len(records) && gap > 0; i += 2 {
		width := gap/2 + 1
		if width > 10 {
			width = 10
		}
		uid := int64(1)
		for j := 1; j < width; j++ {
			uid *= 10
		}
		records[i].UID = uid
		records[i+1].UID = uid
		gap -= 2 * (width - 1)
	}
	if gap != 0 {
		t.Fatalf("unfilled gap %d", gap)
	}
	var out []byte
	prev := ZeroHash
	for _, r := range records {
		r.Prev = prev
		b, e := Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, b...)
		prev = Digest(b)
	}
	if len(out) != size {
		t.Fatalf("size %d want %d", len(out), size)
	}
	return out
}

// The constants are attainable canonical maxima, including LF, with adjacent legal states bounded by them.
func TestCapacityRecordBounds(t *testing.T) {
	for _, x := range []struct {
		state string
		size  int
	}{{"retiring", 265}, {"removed", 264}, {"creating", 265}, {"active", 263}} {
		b, e := Encode(Record{MaxSeq, strings.Repeat("f", 64), 4294967294, capacityToken, x.state, "operator-manual", "9999-12-31T23:59:59Z"})
		wantCode(t, e, "ok")
		if len(b) != x.size {
			t.Fatalf("%s length %d", x.state, len(b))
		}
	}
	if MaxRetiringRecord != 265 || MaxRemovedRecord != 264 {
		t.Fatal("reserve constants changed")
	}
}

// At equality an active neighbor releases; new growth refuses without mutation,
// then real manual retirement and removal spend their own reserve and still succeed.
func TestCapacityReserveLifecycle(t *testing.T) {
	b := sizedCapacityHistory(t, MaxFile-529, "active")
	dir, p := fixture(t, b)
	tool := testTool(t, p)
	released := false
	e := withActive(context.Background(), dir, genesis, capacityUID, capacityToken, p, func(View, time.Time) error { released = true; return nil })
	wantCode(t, e, "ok")
	if !released {
		t.Fatal("valid reserve did not release")
	}
	out, e := runbook(t, tool, p, "append", dir, "0", ZeroHash, "1", "4294967294", "2", token, "creating", "2026-10-01T00:00:00Z")
	if e == nil || !strings.Contains(out, "journal_capacity_reserve") {
		t.Fatalf("new creating: %v %.160s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(b, after) {
		t.Fatal("reserve refusal mutated history")
	}
	if _, e = os.Stat(filepath.Join(dir, "writer.pending")); e != nil {
		t.Fatal("refusal lost marker")
	}
	out, e = runbook(t, tool, p, "reconcile", dir, "0", ZeroHash)
	if e != nil {
		t.Fatalf("valid-reserve reconciliation: %v %.160s", e, out)
	}
	for _, state := range []string{"retiring", "removed"} {
		out, e = runbook(t, tool, p, "append", dir, "0", ZeroHash, "1", "4294967294", fmt.Sprint(capacityUID), capacityToken, state, "2026-10-01T00:00:00Z")
		if e != nil {
			t.Fatalf("reserved %s: %v %.160s", state, e, out)
		}
		stored, _ := os.ReadFile(filepath.Join(dir, "journal"))
		v, e := Verify(bytes.NewReader(stored), genesis)
		wantCode(t, e, "ok")
		wantCode(t, v.Capacity(), "ok")
	}
}

// A one-byte reserve deficit closes every UID and preserves reconciliation evidence;
// diagnostic verification still accepts intact bytes and the independently supplied floor.
func TestCapacityReserveDeficit(t *testing.T) {
	b := sizedCapacityHistory(t, MaxFile-528, "active")
	v, e := Verify(bytes.NewReader(b), genesis)
	wantCode(t, e, "ok")
	for _, uid := range []int64{capacityUID, 1, 2} {
		wantCode(t, v.Active(uid, capacityToken), "journal_capacity_reserve")
	}
	dir, p := fixture(t, b)
	tool := testTool(t, p)
	_, e = inspect(context.Background(), dir, v.Tail, p)
	wantCode(t, e, "ok")
	called := false
	e = withActive(context.Background(), dir, v.Tail, capacityUID, capacityToken, p, func(View, time.Time) error { called = true; return nil })
	wantCode(t, e, "journal_capacity_reserve")
	if called {
		t.Fatal("invalid reserve released")
	}
	// The proposed retiring state would fit, but a preexisting invalid reserve is migration-only.
	out, e := runbook(t, tool, p, "append", dir, fmt.Sprint(v.Tail.Seq), v.Tail.Hash, "1", "4294967294", fmt.Sprint(capacityUID), capacityToken, "retiring", "2026-10-01T00:00:00Z")
	if e == nil || !strings.Contains(out, "journal_capacity_reserve") {
		t.Fatalf("legacy invalid reserve append: %v %.160s", e, out)
	}
	marker, _ := os.ReadFile(filepath.Join(dir, "writer.pending"))
	out, e = runbook(t, tool, p, "reconcile", dir, fmt.Sprint(v.Tail.Seq), v.Tail.Hash)
	if e == nil || !strings.Contains(out, "journal_capacity_reserve") {
		t.Fatalf("invalid-reserve reconcile: %v %.160s", e, out)
	}
	kept, _ := os.ReadFile(filepath.Join(dir, "writer.pending"))
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(marker, kept) || !bytes.Equal(b, after) {
		t.Fatal("reconciliation changed evidence")
	}
}

// A creating generation at the reserve boundary cannot activate but can still record
// direct removed after rollback; it does not need an invalid retiring transition.
func TestCapacityCreationRollback(t *testing.T) {
	b := sizedCapacityHistory(t, MaxFile-529, "creating")
	dir, p := fixture(t, b)
	tool := testTool(t, p)
	out, e := runbook(t, tool, p, "append", dir, "0", ZeroHash, "1", "4294967294", fmt.Sprint(capacityUID), capacityToken, "active", "2026-10-01T00:00:00Z")
	if e == nil || !strings.Contains(out, "journal_capacity_reserve") {
		t.Fatalf("activation spent retirement reserve: %v %.160s", e, out)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "journal"))
	if !bytes.Equal(after, b) {
		t.Fatal("refused activation mutated history")
	}
	out, e = runbook(t, tool, p, "reconcile", dir, "0", ZeroHash)
	if e != nil {
		t.Fatalf("reconcile: %v %.160s", e, out)
	}
	out, e = runbook(t, tool, p, "append", dir, "0", ZeroHash, "1", "4294967294", fmt.Sprint(capacityUID), capacityToken, "removed", "2026-10-01T00:00:00Z")
	if e != nil {
		t.Fatalf("rollback: %v %.160s", e, out)
	}
	stored, _ := os.ReadFile(filepath.Join(dir, "journal"))
	v, e := Verify(bytes.NewReader(stored), genesis)
	wantCode(t, e, "ok")
	wantCode(t, v.Capacity(), "ok")
	wantCode(t, v.Active(capacityUID, capacityToken), "generation_inactive")
}
