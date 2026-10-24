//go:build linux

package linuxos

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/swarma-registrar/ccj"
	"golang.org/x/sys/unix"
)

const userDBMessageMax = 64 << 10
const userDBTotalMax = 8 << 20
const userDBInterface = "io.systemd.UserDatabase."

type userDBBudget struct{ records, bytes int }

// Objects are closed at every layer. CCJ parsing additionally rejects duplicate
// keys (including escaped aliases), invalid Unicode and nonintegral numbers.
// Wire JSON need not use the canonical manifest encoding.
func userDBObject(b []byte, allowed ...string) (map[string]json.RawMessage, error) {
	fail := func() (map[string]json.RawMessage, error) {
		return nil, refusal("directory_unknown", "userdb_json", nil)
	}
	if _, e := ccj.Parse(b, ccj.RegistrationMalformed); e != nil {
		return fail()
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil || obj == nil {
		return fail()
	}
	for k, v := range obj {
		found := false
		for _, name := range allowed {
			found = found || k == name
		}
		if !found || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fail()
		}
	}
	return obj, nil
}

// Each request uses a fresh connection. After a terminal frame, shutdown the
// write side and drain to EOF, rejecting ANY further byte, including a delayed
// or partial extra frame. sd-varlink disconnects idle servers on read EOF after
// flushing queued output. A provider that never disconnects remains unknown;
// a quiet interval is never interpreted as completion.
func userDBCall(ctx context.Context, parent *Dir, name, method string, before unix.Stat_t, limits Limits, used *userDBBudget) (rows []json.RawMessage, err error) {
	fail := func(e error) ([]json.RawMessage, error) { return nil, refusal("directory_unknown", "userdb_stream", e) }
	path := "/proc/self/fd/" + number(uint32(parent.f.Fd())) + "/" + name
	connection, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return fail(e)
	}
	defer func() {
		err = errors.Join(err, connection.Close())
		if err != nil {
			rows = nil
		}
	}()
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return fail(nil)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return fail(nil)
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return fail(e)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	raw, e := conn.SyscallConn()
	if e != nil {
		return fail(e)
	}
	var peer *unix.Ucred
	var peerErr error
	if e = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); e != nil || peerErr != nil || peer == nil || peer.Pid <= 0 || peer.Uid != parent.owner || peer.Gid != parent.group {
		return fail(errors.Join(e, peerErr))
	}
	check := func() error {
		f, e := child(parent.f, name, unix.O_PATH, 0)
		if e != nil {
			return e
		}
		defer f.Close()
		st, e := descriptorStat(f)
		if e != nil || !stableStat(before, st) {
			return refusal("directory_unknown", "userdb_endpoint_changed", e)
		}
		return ctx.Err()
	}
	if e = check(); e != nil {
		return fail(e)
	}
	request, e := json.Marshal(struct {
		Method     string            `json:"method"`
		Parameters map[string]string `json:"parameters"`
		More       bool              `json:"more"`
	}{userDBInterface + method, map[string]string{"service": name}, true})
	if e != nil {
		return fail(e)
	}
	if _, e = io.Copy(conn, bytes.NewReader(append(request, 0))); e != nil {
		return fail(e)
	}
	reader := bufio.NewReaderSize(conn, userDBMessageMax+1)
	for {
		frame, e := reader.ReadSlice(0)
		used.bytes += len(frame)
		if e != nil || len(frame) > userDBMessageMax || used.bytes > userDBTotalMax {
			return fail(e)
		}
		reply, e := userDBObject(frame[:len(frame)-1], "parameters", "continues", "error")
		if e != nil {
			return fail(e)
		}
		continues := false
		if b, ok := reply["continues"]; ok && json.Unmarshal(b, &continues) != nil {
			return fail(nil)
		}
		if failure, ok := reply["error"]; ok {
			var name string
			if json.Unmarshal(failure, &name) != nil || name != userDBInterface+"NoRecordFound" || continues || len(rows) != 0 {
				return fail(nil)
			}
			if p, ok := reply["parameters"]; ok {
				obj, e := userDBObject(p)
				if e != nil || len(obj) != 0 {
					return fail(e)
				}
			}
		} else {
			p, ok := reply["parameters"]
			if !ok {
				return fail(nil)
			}
			used.records++
			if used.records > limits.Entries {
				return fail(nil)
			}
			rows = append(rows, bytes.Clone(p))
		}
		if continues {
			continue
		}
		if e = conn.CloseWrite(); e != nil {
			return fail(e)
		}
		if _, e = reader.ReadByte(); e != io.EOF {
			return fail(e)
		}
		if e = check(); e != nil {
			return fail(e)
		}
		return rows, nil
	}
}

func userDBText(s string, name bool) bool {
	if s == "" || !utf8.ValidString(s) || len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ':' || name && (r == ',' || unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}
func userDBPath(s string) bool {
	return userDBText(s, false) && filepath.IsAbs(s) && filepath.Clean(s) == s
}
func userDBInRange(id uint32, intervals []IDInterval) bool {
	if id == ^uint32(0) {
		return false
	}
	for _, v := range intervals {
		if id >= v.Min && id <= v.Max {
			return true
		}
	}
	return false
}

type userDBProjection struct {
	data        NSSDatabases
	memberships map[string]map[string]bool
}

func newUserDBProjection() *userDBProjection {
	return &userDBProjection{NSSDatabases{"passwd": {}, "group": {}, "shadow": {}}, map[string]map[string]bool{}}
}

func (p *userDBProjection) provider(service UserDBService, method string, rows []json.RawMessage) error {
	fail := func() error { return refusal("directory_unknown", "userdb_record", nil) }
	names, numbers := map[string]bool{}, map[uint32]bool{}
	for _, row := range rows {
		switch method {
		case "GetUserRecord", "GetGroupRecord":
			params, e := userDBObject(row, "record", "incomplete")
			if e != nil || params["record"] == nil {
				return fail()
			}
			if b, ok := params["incomplete"]; ok {
				var incomplete bool
				if json.Unmarshal(b, &incomplete) != nil || incomplete {
					return fail()
				}
			}
			allowed := []string{"groupName", "gid", "service", "description", "disposition"}
			if method == "GetUserRecord" {
				allowed = []string{"userName", "uid", "gid", "homeDirectory", "shell", "locked", "service", "realName", "disposition"}
			}
			record, e := userDBObject(params["record"], allowed...)
			if e != nil {
				return fail()
			}
			var v struct {
				UserName, GroupName, HomeDirectory, Shell, Service string
				UID, GID                                           *uint32
				Locked                                             *bool
				RealName, Description, Disposition                 string
			}
			if json.Unmarshal(params["record"], &v) != nil || v.Service != service.Name || v.GID == nil || !userDBInRange(*v.GID, service.GIDRanges) {
				return fail()
			}
			// Optional metadata is typed, even though it does not enter the closed NSS
			// projection. Unsupported account/privileged/per-machine fields refuse.
			for _, k := range []string{"realName", "description", "disposition"} {
				if b, ok := record[k]; ok {
					var s string
					if json.Unmarshal(b, &s) != nil || strings.IndexFunc(s, unicode.IsControl) >= 0 {
						return fail()
					}
				}
			}
			name, id := v.GroupName, *v.GID
			db, line := "group", ""
			if method == "GetUserRecord" {
				if v.UID == nil || v.Locked == nil || !userDBInRange(*v.UID, service.UIDRanges) || !userDBPath(v.HomeDirectory) || !userDBPath(v.Shell) {
					return fail()
				}
				name, id, db = v.UserName, *v.UID, "passwd"
				line = name + ":x:" + number(id) + ":" + number(*v.GID) + "::" + v.HomeDirectory + ":" + v.Shell + "\n"
			} else {
				line = name + ":x:" + number(id) + ":\n"
			}
			if !userDBText(name, true) || names[name] || numbers[id] {
				return fail()
			}
			names[name], numbers[id] = true, true
			p.data[db] = append(p.data[db], []byte(line)...)
			if method == "GetUserRecord" {
				marker := ""
				if *v.Locked {
					marker = "!"
				}
				p.data["shadow"] = append(p.data["shadow"], []byte(name+":"+marker+":::::::\n")...)
			}
		case "GetMemberships":
			obj, e := userDBObject(row, "userName", "groupName")
			var v struct{ UserName, GroupName string }
			if e != nil || len(obj) != 2 || json.Unmarshal(row, &v) != nil || !userDBText(v.UserName, true) || !userDBText(v.GroupName, true) {
				return fail()
			}
			key := v.UserName + ":" + v.GroupName
			if names[key] {
				return fail()
			}
			names[key] = true
			if p.memberships[v.GroupName] == nil {
				p.memberships[v.GroupName] = map[string]bool{}
			}
			p.memberships[v.GroupName][v.UserName] = true
		default:
			return fail()
		}
	}
	return nil
}

func (p *userDBProjection) finish(files NSSDatabases, l Limits) (NSSDatabases, error) {
	out := NSSDatabases{}
	for _, db := range []string{"passwd", "group", "shadow"} {
		out[db] = append(bytes.Clone(files[db]), p.data[db]...)
	}
	if e := validateDirectoryDatabases(out, l.Entries, true); e != nil {
		return nil, e
	}
	users := map[string]bool{}
	for _, line := range strings.Split(string(out["passwd"]), "\n") {
		if line != "" {
			users[strings.Split(line, ":")[0]] = true
		}
	}
	groups := map[string]bool{}
	var group strings.Builder
	for _, line := range strings.Split(string(out["group"]), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		groups[f[0]] = true
		members := map[string]bool{}
		if f[3] != "" {
			for _, m := range strings.Split(f[3], ",") {
				members[m] = true
			}
		}
		for m := range p.memberships[f[0]] {
			if !users[m] {
				return nil, refusal("directory_unknown", "userdb_membership_user", nil)
			}
			members[m] = true
		}
		sorted := []string{}
		for m := range members {
			sorted = append(sorted, m)
		}
		sort.Strings(sorted)
		f[3] = strings.Join(sorted, ",")
		group.WriteString(strings.Join(f, ":") + "\n")
	}
	for name := range p.memberships {
		if !groups[name] {
			return nil, refusal("directory_unknown", "userdb_membership_group", nil)
		}
	}
	out["group"] = []byte(group.String())
	if e := validateDirectoryDatabases(out, l.Entries, true); e != nil {
		return nil, e
	}
	return out, nil
}

// Compare only the directory's closed fields, on ALL observed records. GECOS,
// group password placeholders and shadow aging fields are not directory fields.
func userDBAgreement(a, b NSSDatabases) bool {
	projection := func(data NSSDatabases) map[string][]string {
		out := map[string][]string{}
		for _, db := range []string{"passwd", "group", "shadow"} {
			out[db] = []string{}
			for _, line := range strings.Split(string(data[db]), "\n") {
				if line == "" {
					continue
				}
				f := strings.Split(line, ":")
				switch db {
				case "passwd":
					f[4] = ""
				case "group":
					f[1] = ""
					members := strings.Split(f[3], ",")
					sort.Strings(members)
					f[3] = strings.Join(members, ",")
				case "shadow":
					f = f[:2]
				}
				out[db] = append(out[db], strings.Join(f, ":"))
			}
			sort.Strings(out[db])
		}
		return out
	}
	return reflect.DeepEqual(projection(a), projection(b))
}

func (r *SystemdNSSRuntime) collectSystemd(ctx context.Context, names []string, l Limits) ([]NSSModule, NSSDatabases, error) {
	fail := func(e error) ([]NSSModule, NSSDatabases, error) {
		return nil, nil, refusal("directory_unknown", "systemd_provider_completion_unavailable", e)
	}
	if !reflect.DeepEqual(names, []string{"files", "systemd"}) {
		return fail(nil)
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return fail(e)
	}
	defer cancel()
	filesModules, e := r.Files.CaptureModules(c, []string{"files"}, l)
	if e != nil {
		return fail(e)
	}
	before, e := r.captureSystemd(c, l)
	if e != nil {
		return fail(e)
	}
	b, e := protectedRead(c, r.Manifest.Directory, r.Manifest.Name, 1<<20, true)
	if e != nil {
		return fail(e)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != before.ConfigurationDigest {
		return fail(nil)
	}
	manifest, e := ParseSystemdClosure(b, l)
	if e != nil {
		return fail(e)
	}
	direct, e := r.enumerateUserDB(c, manifest, l)
	if e != nil {
		return fail(e)
	}
	files, e := r.Files.Enumerate(c, []string{"files"}, l)
	if e != nil {
		return fail(e)
	}
	expected, e := direct.finish(files, l)
	if e != nil {
		return fail(e)
	}
	nss, e := enumerateNSS(c, r.Files.Collector, []ProtectedArtifact{r.Files.Library, r.Library}, l)
	if e != nil {
		return fail(e)
	}
	if !userDBAgreement(expected, nss) {
		return fail(refusal("directory_unknown", "userdb_nss_agreement", nil))
	}
	after, e := r.captureSystemd(c, l)
	if e != nil || !reflect.DeepEqual(before, after) {
		return fail(e)
	}
	filesAfter, e := r.Files.CaptureModules(c, []string{"files"}, l)
	if e != nil || !reflect.DeepEqual(filesModules, filesAfter) {
		return fail(e)
	}
	if e = c.Err(); e != nil {
		return fail(e)
	}
	// Publish namespace evidence only after every direct stream, NSS agreement
	// and final metadata/file check succeeded.
	r.mu.Lock()
	r.completedNamespace = namespaceFingerprint(after.ConfigurationDigest, r.observed)
	r.mu.Unlock()
	return append(filesModules, before), expected, nil
}

func (r *SystemdNSSRuntime) enumerateUserDB(ctx context.Context, m SystemdClosureManifest, l Limits) (out *userDBProjection, err error) {
	defer func() {
		if err != nil {
			out = nil
		}
	}()
	fail := func(e error) (*userDBProjection, error) { return nil, refusal("directory_unknown", "userdb_direct", e) }
	if !l.valid() {
		return fail(nil)
	}
	parent, e := r.Run.OpenDirectory("systemd")
	if e != nil {
		return fail(e)
	}
	defer closed(parent.f, &err)
	if e = parent.protected(); e != nil {
		return fail(e)
	}
	dir, e := parent.OpenDirectory("userdb")
	if e != nil {
		return fail(e)
	}
	defer closed(dir.f, &err)
	if e = dir.protected(); e != nil {
		return fail(e)
	}
	out = newUserDBProjection()
	used := &userDBBudget{}
	for _, s := range m.Services {
		// The manifest fixes Multiplexer's contributor set and NSS's files-only
		// forward. Query those underlying providers directly; never trust a bridge's
		// lossy aggregate completion, even when its socket is present and protected.
		if isUserDBBridge(s.Name) {
			continue
		}
		f, e := child(dir.f, s.Name, unix.O_PATH, 0)
		if e != nil {
			return fail(e)
		}
		defer closed(f, &err)
		st, se := descriptorStat(f)
		if se != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != dir.owner || st.Gid != dir.group || st.Nlink != 1 {
			return fail(se)
		}
		r.mu.Lock()
		pinned, ok := r.observed["/run/systemd/userdb/"+s.Name]
		r.mu.Unlock()
		if !ok || !stableStat(pinned, st) {
			return fail(nil)
		}
		for _, method := range []string{"GetUserRecord", "GetGroupRecord", "GetMemberships"} {
			rows, e := userDBCall(ctx, dir, s.Name, method, st, l, used)
			if e != nil {
				return fail(e)
			}
			if e = out.provider(s, method, rows); e != nil {
				return fail(e)
			}
		}
	}
	return out, nil
}
