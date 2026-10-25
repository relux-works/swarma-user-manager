//go:build linux

package genjournal

import (
	"bytes"
	"testing"
)

// Claim: pure census adapters preserve existing complete marker/record bytes,
// reject missing LF/malformed native input, and confer no owner/clock authority.
func TestCensusNativeByteValidators(t *testing.T) {
	marker, e := encodePending(pendingRecord{"00000000-0000-4000-8000-000000000001", 1, 1000})
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidatePendingBytes(marker); e != nil {
		t.Fatal(e)
	}
	for _, raw := range [][]byte{marker[:len(marker)-1], []byte("{}\n"), append(bytes.Clone(marker), '\n')} {
		if e := ValidatePendingBytes(raw); e == nil {
			t.Fatal("malformed marker accepted")
		}
	}
	line, e := Encode(Record{Seq: 1, Prev: ZeroHash, UID: 10, Generation: "11111111111111111111111111111111", State: "active", Writer: "user-manager", Time: "2026-10-25T00:00:00Z"})
	if e != nil {
		t.Fatal(e)
	}
	if r, e := DecodeRecordBytes(line); e != nil || r.UID != 10 {
		t.Fatal(r, e)
	}
	for _, raw := range [][]byte{line[:len(line)-1], []byte("{}\n"), append(bytes.Clone(line), '\n')} {
		if _, e := DecodeRecordBytes(raw); e == nil {
			t.Fatal("malformed record accepted")
		}
	}
}
