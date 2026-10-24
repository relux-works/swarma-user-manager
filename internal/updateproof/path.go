package updateproof

import (
	"path"
	"strings"
)

func leafPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\n\r")
}
