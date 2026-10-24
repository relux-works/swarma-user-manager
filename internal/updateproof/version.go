package updateproof

import (
	"regexp"
	"strings"
)

var versionRE = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+:~\-]*$`)

func validVersion(v string) bool { return len(v) <= 256 && versionRE.MatchString(v) }
func trimNum(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
func numCompare(a, b string) int {
	a = trimNum(a)
	b = trimNum(b)
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}
func order(c byte) int {
	if c == '~' {
		return -1
	}
	if c == 0 {
		return 0
	}
	if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
		return int(c)
	}
	return int(c) + 256
}
func digit(c byte) bool { return c >= '0' && c <= '9' }
func partCompare(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && !digit(a[0]) || len(b) > 0 && !digit(b[0]) {
			var x, y byte
			if len(a) > 0 {
				x = a[0]
			}
			if len(b) > 0 {
				y = b[0]
			}
			ox, oy := order(x), order(y)
			if digit(x) {
				ox = 0
			}
			if digit(y) {
				oy = 0
			}
			if ox < oy {
				return -1
			}
			if ox > oy {
				return 1
			}
			if len(a) > 0 {
				a = a[1:]
			}
			if len(b) > 0 {
				b = b[1:]
			}
		}
		i, j := 0, 0
		for i < len(a) && digit(a[i]) {
			i++
		}
		for j < len(b) && digit(b[j]) {
			j++
		}
		if c := numCompare(a[:i], b[:j]); c != 0 {
			return c
		}
		a = a[i:]
		b = b[j:]
	}
	return 0
}

// CompareVersions implements Debian epoch/upstream/revision ordering. Inputs
// must first pass validVersion; no subprocess or lexical version comparison.
func CompareVersions(a, b string) int {
	split := func(v string) (string, string, string) {
		epoch := "0"
		if i := strings.IndexByte(v, ':'); i >= 0 {
			epoch = v[:i]
			v = v[i+1:]
		}
		revision := "0"
		if i := strings.LastIndexByte(v, '-'); i >= 0 {
			revision = v[i+1:]
			v = v[:i]
		}
		return epoch, v, revision
	}
	ae, au, ar := split(a)
	be, bu, br := split(b)
	if c := numCompare(ae, be); c != 0 {
		return c
	}
	if c := partCompare(au, bu); c != 0 {
		return c
	}
	return partCompare(ar, br)
}
