package slotd

import (
	"bytes"
	"strings"
	"testing"
)

// Proves bounded LF framing accepts the maximum JSON object but refuses oversized, incomplete and failed reads.
func TestReadFrame(t *testing.T) {
	for _, size := range []int{2, maxRequestBytes, maxRequestBytes + 1} {
		input := strings.Repeat(" ", size-2) + "{}\n"
		got, code := readFrame(strings.NewReader(input))
		want := errorCode("")
		if size > maxRequestBytes {
			want = badRequest
		}
		if code != want || (code == "" && string(got) != input) || (code != "" && got != nil) {
			t.Fatalf("size=%d code=%s length=%d", size, code, len(got))
		}
	}
	for _, input := range []string{"", "{}", strings.Repeat("x", maxRequestBytes+2)} {
		if got, code := readFrame(strings.NewReader(input)); code != badRequest || got != nil {
			t.Fatalf("unterminated input accepted, length %d", len(input))
		}
	}
	if got, code := readFrame(bytes.NewReader([]byte("{}\n{}\n"))); code != "" || string(got) != "{}\n" {
		t.Fatal("first frame not read exactly")
	}
}

// Proves peer UID equality alone admits the configured caller; a different UID including root is forbidden.
func TestAuthorizePeer(t *testing.T) {
	for _, tc := range []struct {
		peer, caller uint32
		want         errorCode
	}{
		{12345, 12345, ""}, {12346, 12345, forbiddenPeer}, {0, 12345, forbiddenPeer},
	} {
		if got := authorizePeer(tc.peer, tc.caller); got != tc.want {
			t.Fatalf("peer %d: %s", tc.peer, got)
		}
	}
}

// Proves a held slot immediately returns busy, another slot proceeds and the original is available after release.
func TestSlotLocks(t *testing.T) {
	var locks slotLocks
	unlock, code := locks.tryLock("17")
	if code != "" {
		t.Fatal(code)
	}
	if release, code := locks.tryLock("17"); release != nil || code != busy {
		t.Fatal("held slot did not refuse busy")
	}
	other, code := locks.tryLock("18")
	if code != "" {
		t.Fatal(code)
	}
	other()
	unlock()
	again, code := locks.tryLock("17")
	if code != "" {
		t.Fatal(code)
	}
	again()
	for _, slot := range []string{"01", "10000", "-1", ""} {
		if release, code := locks.tryLock(slot); release != nil || code != invalidSlot {
			t.Fatalf("invalid slot %q accepted", slot)
		}
	}
}
