package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxPolicyBytes = 64 * 1024

type policy struct {
	CallerUser string        `json:"caller_user"`
	UIDBase    uint32        `json:"uid_base"`
	HomeRoot   string        `json:"home_root"`
	Socket     string        `json:"socket"`
	Payload    payloadPolicy `json:"payload"`
	Caps       capsPolicy    `json:"caps"`
	Egress     []egressRule  `json:"egress"`
}

type payloadPolicy struct {
	Path   string   `json:"path"`
	SHA256 string   `json:"sha256"`
	Argv   []string `json:"argv"`
}

type capsPolicy struct {
	CPUQuota  string `json:"cpu_quota"`
	MemoryMax string `json:"memory_max"`
	TasksMax  uint32 `json:"tasks_max"`
}

type egressRule struct {
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

var (
	userPattern   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	cpuPattern    = regexp.MustCompile(`^[1-9][0-9]{0,5}(\.[0-9]{1,3})?%$|^0\.[0-9]{1,3}%$`)
	memoryPattern = regexp.MustCompile(`^[1-9][0-9]{0,17}[KMGT]?$`)
)

// parsePolicy validates configuration bytes only. The Linux loader must also
// prove ownership, modes and descriptor ancestry before trusting these bytes.
func parsePolicy(b []byte) (policy, error) {
	var p policy
	if len(b) > maxPolicyBytes {
		return p, errors.New("policy too large")
	}
	f, ok := objectFields(b, "caller_user", "uid_base", "home_root", "socket", "payload", "caps", "egress")
	if !ok || len(f) != 7 {
		return p, errors.New("invalid policy fields")
	}
	if !decodeFields(f, map[string]any{
		"caller_user": &p.CallerUser, "uid_base": &p.UIDBase, "home_root": &p.HomeRoot, "socket": &p.Socket,
	}) {
		return p, errors.New("invalid policy value types")
	}
	payload, ok := objectFields(f["payload"], "path", "sha256", "argv")
	if !ok || len(payload) != 3 || !decodeFields(payload, map[string]any{"path": &p.Payload.Path, "sha256": &p.Payload.SHA256, "argv": &p.Payload.Argv}) {
		return p, errors.New("invalid payload fields")
	}
	var rawArgv []json.RawMessage
	if json.Unmarshal(payload["argv"], &rawArgv) != nil {
		return p, errors.New("invalid payload argv")
	}
	for _, arg := range rawArgv {
		if len(arg) == 0 || arg[0] != '"' {
			return p, errors.New("invalid payload argument type")
		}
	}
	caps, ok := objectFields(f["caps"], "cpu_quota", "memory_max", "tasks_max")
	if !ok || len(caps) != 3 || !decodeFields(caps, map[string]any{"cpu_quota": &p.Caps.CPUQuota, "memory_max": &p.Caps.MemoryMax, "tasks_max": &p.Caps.TasksMax}) {
		return p, errors.New("invalid caps fields")
	}
	var entries []json.RawMessage
	if !decodeFields(f, map[string]any{"egress": &entries}) || len(entries) > 256 {
		return p, errors.New("invalid egress list")
	}
	for _, raw := range entries {
		fields, ok := objectFields(raw, "addr", "port", "proto")
		var rule egressRule
		if !ok || len(fields) != 3 || !decodeFields(fields, map[string]any{"addr": &rule.Addr, "port": &rule.Port, "proto": &rule.Proto}) {
			return p, errors.New("invalid egress fields")
		}
		p.Egress = append(p.Egress, rule)
	}
	return p, p.validate()
}

func decodeFields(fields map[string]json.RawMessage, targets map[string]any) bool {
	for key, target := range targets {
		b, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(b), []byte("null")) || json.Unmarshal(b, target) != nil {
			return false
		}
	}
	return true
}

func cleanAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && path.Clean(value) == value && plainText(value)
}

func plainText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (p policy) validate() error {
	if !userPattern.MatchString(p.CallerUser) || p.CallerUser == "root" || strings.HasPrefix(p.CallerUser, "worker-slot-") {
		return errors.New("invalid caller account")
	}
	// The exact-ID linuxos allocator rejects zero and the uint32 sentinel.
	if p.UIDBase == 0 || uint64(p.UIDBase)+9999 >= uint64(^uint32(0)) || (p.UIDBase <= 65534 && uint64(p.UIDBase)+9999 >= 65534) {
		return errors.New("invalid slot UID range")
	}
	// Home paths become passwd fields. Reject their delimiter before groupadd
	// can succeed ahead of a predictable useradd argument rejection.
	if !cleanAbsolutePath(p.HomeRoot) || strings.ContainsRune(p.HomeRoot, ':') || !cleanAbsolutePath(p.Socket) || len(p.Socket) >= 108 || strings.HasPrefix(p.Socket, p.HomeRoot+"/") || p.Socket == p.HomeRoot {
		return errors.New("invalid home or socket path")
	}
	if !cleanAbsolutePath(p.Payload.Path) || strings.HasPrefix(p.Payload.Path, p.HomeRoot+"/") || !digestPattern.MatchString(p.Payload.SHA256) || len(p.Payload.Argv) == 0 || len(p.Payload.Argv) > 128 || p.Payload.Argv[0] != p.Payload.Path {
		return errors.New("invalid payload binding")
	}
	argvBytes := 0
	for _, arg := range p.Payload.Argv {
		if !plainText(arg) {
			return errors.New("invalid payload argument")
		}
		argvBytes += len(arg) + 1
	}
	if argvBytes > 32768 {
		return errors.New("payload argv too large")
	}
	cpu, err := strconv.ParseFloat(strings.TrimSuffix(p.Caps.CPUQuota, "%"), 64)
	if !cpuPattern.MatchString(p.Caps.CPUQuota) || err != nil || cpu <= 0 || !validMemoryMax(p.Caps.MemoryMax) || p.Caps.TasksMax == 0 {
		return errors.New("invalid resource caps")
	}
	seen := make(map[egressRule]bool)
	for _, rule := range p.Egress {
		addr, err := netip.ParseAddr(rule.Addr)
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || addr.String() != rule.Addr || rule.Port == 0 || (rule.Proto != "tcp" && rule.Proto != "udp") || seen[rule] {
			return errors.New("invalid egress rule")
		}
		seen[rule] = true
	}
	return nil
}

func validMemoryMax(value string) bool {
	if !memoryPattern.MatchString(value) {
		return false
	}
	shift := uint(0)
	switch value[len(value)-1] {
	case 'K':
		shift = 10
	case 'M':
		shift = 20
	case 'G':
		shift = 30
	case 'T':
		shift = 40
	}
	number := value
	if shift != 0 {
		number = value[:len(value)-1]
	}
	n, err := strconv.ParseUint(number, 10, 64)
	return err == nil && n > 0 && n <= uint64(1<<63-1)>>shift
}

type slotIdentity struct {
	Name, Home, Unit, Table string
	UID                     uint32
}

func (p policy) identity(slot string) (slotIdentity, error) {
	if !slotPattern.MatchString(slot) {
		return slotIdentity{}, errors.New("invalid slot")
	}
	if err := p.validate(); err != nil {
		return slotIdentity{}, err
	}
	n, _ := strconv.ParseUint(slot, 10, 32)
	name := "worker-slot-" + slot
	return slotIdentity{Name: name, Home: path.Join(p.HomeRoot, name), Unit: "swarma-slot-" + slot + ".service", Table: "swarma_slot_" + slot, UID: p.UIDBase + uint32(n)}, nil
}
