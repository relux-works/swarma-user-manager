package updateproof

import (
	"bytes"
	"strconv"
	"strings"
)

// Deliberately strict deb822 subset: duplicate fields, CR/NUL, unsupported
// continuation syntax and oversized fields refuse instead of choosing a stanza.
func parseParagraphs(b []byte) ([]map[string]string, error) {
	if bytes.ContainsAny(b, "\x00\r") || len(b) > 128<<20 {
		return nil, ErrChain
	}
	var out []map[string]string
	cur := map[string]string{}
	last := ""
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
			last = ""
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if len(line) > 1<<20 {
			return nil, ErrChain
		}
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == "" {
				return nil, ErrChain
			}
			cur[last] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return nil, ErrChain
		}
		if _, ok := cur[k]; ok {
			return nil, ErrChain
		}
		cur[k] = strings.TrimSpace(v)
		last = k
	}
	flush()
	if len(out) == 0 {
		return nil, ErrChain
	}
	return out, nil
}
func parseOne(b []byte) (map[string]string, error) {
	s, e := parseParagraphs(b)
	if e != nil || len(s) != 1 {
		return nil, ErrChain
	}
	return s[0], nil
}
func matchesSizeHash(size, hash string, b []byte) bool {
	n, e := strconv.ParseInt(size, 10, 64)
	return e == nil && n >= 0 && n == int64(len(b)) && digestOK(hash) && hash == Digest(b)
}
func signedIndex(field, name string, b []byte) bool {
	found := false
	for _, line := range strings.Split(field, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 || !digestOK(f[0]) {
			return false
		}
		if f[2] == name {
			if found || !matchesSizeHash(f[1], f[0], b) {
				return false
			}
			found = true
		}
	}
	return found
}
func selectPackage(stanzas []map[string]string, p Package) (map[string]string, error) {
	var chosen map[string]string
	for _, s := range stanzas {
		if s["Package"] == p.Name && s["Version"] == p.Version && s["Architecture"] == p.Architecture {
			if chosen != nil {
				return nil, ErrChain
			}
			chosen = s
		}
	}
	if chosen == nil {
		return nil, ErrChain
	}
	return chosen, nil
}
