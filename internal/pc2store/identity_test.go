package pc2store

import (
	"bytes"
	"strings"
	"testing"
)

// Claim: the exact joint ordered arrays (without LF) produce independently
// calculated IDs; unsafe identities cannot become admitted copy locations.
func TestPC2StorageIDGrammar(t *testing.T) {
	i := CopyIdentity{"deployment", "incarnation", "manager", "inventory", "inventory", "inventory/00000000000000000000000000000001/" + strings.Repeat("a", 64) + ".json", "00000000000000000000000000000001", 1, "sha256:" + strings.Repeat("a", 64)}
	got, e := StorageID(i)
	if e != nil || got != "pc2o1:dc3f3de84fddd89516122e32ac2cfbf6e0052f6073a2db9cad19006f000a89c8" {
		t.Fatal(got, e)
	}
	ticket, e := TicketID(i.ContentDigest, "keymaker", "reservation_metadata", "inventory", 1)
	if e != nil || ticket != "pc2t1:30c3ffbba9022ea10d1ef310c4c0efc5565960bd556ac24f3d1a2a87dee37792" {
		t.Fatal(ticket, e)
	}
	for _, bad := range []func(*CopyIdentity){func(v *CopyIdentity) { v.RelativeName = "../outside" }, func(v *CopyIdentity) { v.RelativeName = "/absolute" }, func(v *CopyIdentity) { v.RelativeName = "inventory//file" }, func(v *CopyIdentity) { v.Owner = "unknown" }, func(v *CopyIdentity) { v.Role = "unknown" }, func(v *CopyIdentity) { v.DirectoryRole = "unknown" }, func(v *CopyIdentity) { v.CopyID = "" }, func(v *CopyIdentity) { v.DispositionVersion = 0 }, func(v *CopyIdentity) { v.ContentDigest = strings.Repeat("a", 64) }, func(v *CopyIdentity) { v.Deployment = "bad\x00text" }} {
		v := i
		bad(&v)
		if _, e := StorageID(v); e == nil {
			t.Fatal("unsafe identity accepted", v)
		}
	}
	if _, e := TicketID(i.ContentDigest, "manager", "inventory", "inventory", 0); e == nil {
		t.Fatal("zero ticket ordinal")
	}
}

// Claim: ownership records are closed canonical bounded records; extra self or
// future-hash members, duplicate members, omitted members and LF are rejected.
func TestPC2StoreRecordGrammar(t *testing.T) {
	b, e := canonical(genesis())
	if e != nil {
		t.Fatal(e)
	}
	var r record
	if decode(b, &r) != nil {
		t.Fatal("valid record rejected")
	}
	for _, bad := range [][]byte{append(append([]byte{}, b...), '\n'), bytes.Replace(b, []byte(`"version":`), []byte(`"self_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":`), 1), bytes.Replace(b, []byte(`"version":`), []byte(`"sequence":0,"version":`), 1), []byte(`{"version":"pc2-owner-transition/1"}`), bytes.Repeat([]byte(" "), maxRecord+1)} {
		if decode(bad, &r) == nil {
			t.Fatal("noncanonical/open record accepted")
		}
	}
}

// Claim: parser work is bounded before decoding; exact depth 16 is allowed
// by this lexical guard, while depth 17 and unclosed containers are rejected.
func TestPC2StoreDepthBound(t *testing.T) {
	if !boundedDepth([]byte(strings.Repeat("[", 16) + "0" + strings.Repeat("]", 16))) {
		t.Fatal("exact depth rejected")
	}
	if boundedDepth([]byte(strings.Repeat("[", 17)+"0"+strings.Repeat("]", 17))) || boundedDepth([]byte("[[")) {
		t.Fatal("unbounded input accepted")
	}
	if !boundedDepth([]byte(`{"text":"[\\\"]"}`)) {
		t.Fatal("quoted bracket altered depth")
	}
}
