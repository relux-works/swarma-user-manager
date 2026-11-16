package manager

import (
	"context"
	"os"
)

// Exported seams for the launcher and exec.stop receiver (internal/launch).
// They expose the existing hardened helpers unchanged; none of them widens the
// closed station-core request schema or the production root/anchor policy.

// AuthorizeCaller applies the invocation and protected caller-record checks of
// the helper entry: no argv, effective UID 0, trusted sudo transition and an
// exact configured caller record. It returns the matched configured caller.
func AuthorizeCaller(ctx context.Context, p Policy, in Invocation, a Authority) (Caller, error) {
	return p.authorize(ctx, in, a)
}

// ProtectedDir opens an absolute directory under anchor component by component
// without following links, requiring the given owner and no group/world write.
func ProtectedDir(path string, owner uint32, anchor string) (*os.File, error) {
	return protectedDir(path, owner, anchor)
}

// ReadProtected reads one regular, single-link, owner-only (0600) file beneath
// an already pinned protected directory, bounded by limit bytes.
func ReadProtected(d *os.File, name string, owner uint32, limit int) ([]byte, error) {
	return readFile(d, name, owner, limit)
}

// WriteProtected atomically replaces (or creates) a 0600 owner-only file
// beneath a pinned protected directory, syncing the file and its directory.
func WriteProtected(d *os.File, name string, b []byte, owner uint32) error {
	return atomicFile(d, name, b, owner)
}

// Strict decodes exactly one closed canonical CCJ-1 object into out: unknown or
// duplicate members, noncanonical bytes and re-encoding drift refuse.
func Strict(b []byte, out any) error { return strict(b, out) }

// ValidGeneration reports the closed 32-lowercase-hex nonzero generation form.
func ValidGeneration(s string) bool { return validGeneration(s) }

// ValidRequestID reports the closed caller-scoped identifier form shared by
// request IDs, execution IDs and principals.
func ValidRequestID(s string) bool { return requestID.MatchString(s) }

// HashOK reports a lowercase 64-hex SHA-256 string.
func HashOK(s string) bool { return hashOK(s) }

// DigestBytes returns the lowercase hex SHA-256 of b.
func DigestBytes(b []byte) string { return digestBytes(b) }

// StateFormat and StoreFormat name the protected station effect evidence
// envelope the launcher reads to bind a generation to its created account.
const (
	StateFormat = stateFormat
	StoreFormat = storeFormat
)
