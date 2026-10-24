package updateproof

import (
	"io"
	"strings"
	"testing"
)

// Claim: tool output stays within its byte cap even through io.Copy's optional
// ReaderFrom fast path; the nearby exact-limit output is preserved unchanged.
func TestUpdateBoundedToolOutput(t *testing.T) {
	for _, tc := range []struct {
		data  string
		limit int64
		want  error
	}{{"valid", 5, nil}, {"oversized", 5, ErrScope}} {
		out := &boundedBuffer{limit: tc.limit}
		// Hide strings.Reader.WriteTo, as an external pipe/copy path can do.
		_, e := io.Copy(out, struct{ io.Reader }{strings.NewReader(tc.data)})
		if e != tc.want || int64(out.Len()) > tc.limit {
			t.Fatalf("bounded output: error=%v bytes=%d limit=%d", e, out.Len(), tc.limit)
		}
		if tc.want == nil && out.String() != tc.data {
			t.Fatal("valid output lost")
		}
	}
}
