//go:build linux

package linuxos

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"
)

// NSSConfiguration is the exact three physical lines, including LF if present.
// It contains configuration only, never passwd/shadow data. Record authentication
// and account-database/configuration exclusion belong to the later Environment.
type NSSConfiguration struct {
	Passwd string `json:"passwd"`
	Group  string `json:"group"`
	Shadow string `json:"shadow"`
}

// CaptureNSSConfiguration only reads protected input. It issues no qualification.
func CaptureNSSConfiguration(ctx context.Context, etc *Dir, l Limits) (NSSConfiguration, []string, error) {
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return NSSConfiguration{}, nil, e
	}
	defer cancel()
	b, e := protectedRead(c, etc, "nsswitch.conf", 1<<20, false)
	if e != nil {
		return NSSConfiguration{}, nil, refusal("directory_unknown", "nss_configuration", e)
	}
	return ParseNSSConfiguration(b, l.Entries)
}

var nssModuleName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ParseNSSConfiguration preserves bytes while recognizing a deliberately closed
// syntax: module names and NSS status/action clauses. All selected modules count,
// including those after a return action. Unsupported syntax refuses.
func ParseNSSConfiguration(b []byte, limit int) (NSSConfiguration, []string, error) {
	fail := func() (NSSConfiguration, []string, error) {
		return NSSConfiguration{}, nil, refusal("directory_unknown", "nss_syntax", nil)
	}
	if limit < 1 || limit > 100000 || len(b) > 1<<20 || !utf8.Valid(b) || strings.ContainsAny(string(b), "\x00\r\\") {
		return fail()
	}
	lines := map[string]string{}
	modules := []string{}
	seen := map[string]bool{}
	for _, physical := range strings.SplitAfter(string(b), "\n") {
		text := strings.TrimSuffix(physical, "\n")
		if at := strings.IndexByte(text, '#'); at >= 0 {
			text = text[:at]
		}
		key, body, ok := strings.Cut(text, ":")
		key = trimNSSSpace(key)
		if key != "passwd" && key != "group" && key != "shadow" {
			continue
		}
		if !ok || lines[key] != "" {
			return fail()
		}
		_, e := nssLineModules(body)
		if e != nil {
			return fail()
		}
		lines[key] = physical
		// Order is constructed below in fixed database order, not file order.
	}
	for _, db := range []string{"passwd", "group", "shadow"} {
		line, ok := lines[db]
		if !ok {
			return fail()
		}
		_, body, _ := strings.Cut(line, ":")
		if at := strings.IndexByte(body, '#'); at >= 0 {
			body = body[:at]
		}
		names, e := nssLineModules(strings.TrimSuffix(body, "\n"))
		if e != nil {
			return fail()
		}
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				modules = append(modules, name)
				if len(modules) > limit {
					return fail()
				}
			}
		}
	}
	return NSSConfiguration{lines["passwd"], lines["group"], lines["shadow"]}, modules, nil
}
func nssLineModules(body string) ([]string, error) {
	names := []string{}
	actionAllowed := false
	fail := func() ([]string, error) { return nil, refusal("directory_unknown", "nss_syntax", nil) }
	for body = trimNSSSpace(body); body != ""; body = trimNSSSpace(body) {
		if body[0] == '[' {
			if !actionAllowed {
				return fail()
			}
			end := strings.IndexByte(body, ']')
			if end < 0 {
				return fail()
			}
			actions := strings.Fields(body[1:end])
			if len(actions) == 0 {
				return fail()
			}
			statuses := map[string]bool{}
			for _, action := range actions {
				status, result, ok := strings.Cut(action, "=")
				status = strings.TrimPrefix(status, "!")
				if !ok || statuses[status] || (status != "SUCCESS" && status != "NOTFOUND" && status != "UNAVAIL" && status != "TRYAGAIN") || (result != "return" && result != "continue" && result != "merge") {
					return fail()
				}
				statuses[status] = true
			}
			body = body[end+1:]
			if body != "" && !nssSpace(rune(body[0])) {
				return fail()
			}
			actionAllowed = false
			continue
		}
		end := strings.IndexAny(body, " \t\v\f")
		if end < 0 {
			end = len(body)
		}
		name := body[:end]
		if !nssModuleName.MatchString(name) {
			return fail()
		}
		names = append(names, name)
		actionAllowed = true
		body = body[end:]
	}
	if len(names) == 0 {
		return fail()
	}
	return names, nil
}

// This closed libc-compatible separator set includes vertical tab/form feed.
// CR and continuations are rejected by the physical-line parser above.
func nssSpace(r rune) bool         { return r == ' ' || r == '\t' || r == '\v' || r == '\f' }
func trimNSSSpace(s string) string { return strings.TrimFunc(s, nssSpace) }
func nssFields(s string) []string  { return strings.FieldsFunc(s, nssSpace) }
