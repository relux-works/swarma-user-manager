package slotd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

const maxPolicyBytes = 64 * 1024

type policy struct {
	Version    int           `json:"version,omitempty"`
	CallerUser string        `json:"caller_user"`
	UIDBase    uint32        `json:"uid_base"`
	HomeRoot   string        `json:"home_root"`
	Socket     string        `json:"socket"`
	Payload    payloadPolicy `json:"payload"`
	Caps       capsPolicy    `json:"caps"`
	Egress     []egressRule  `json:"egress"`
}

type payloadPolicy struct {
	Path           string                 `json:"path,omitempty"`
	SHA256         string                 `json:"sha256,omitempty"`
	Argv           []string               `json:"argv,omitempty"`
	StationProfile *payloadlaunch.Profile `json:"station_profile,omitempty"`
}

func (p policy) payloadPath() string {
	if p.Payload.StationProfile != nil {
		return p.Payload.StationProfile.Executable
	}
	return p.Payload.Path
}
func (p policy) payloadDigest() string {
	if p.Payload.StationProfile != nil {
		return p.Payload.StationProfile.ExecutableSHA256
	}
	return p.Payload.SHA256
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
	f, ok := objectFields(b, "version", "caller_user", "uid_base", "home_root", "socket", "payload", "caps", "egress")
	if !ok || (len(f) != 7 && len(f) != 8) {
		return p, errors.New("invalid policy fields")
	}
	if _, present := f["version"]; present {
		if len(f) != 8 || !decodeFields(f, map[string]any{"version": &p.Version}) || p.Version != 2 {
			return p, errors.New("unsupported policy version")
		}
	} else if len(f) != 7 {
		return p, errors.New("invalid policy fields")
	}
	if !decodeFields(f, map[string]any{
		"caller_user": &p.CallerUser, "uid_base": &p.UIDBase, "home_root": &p.HomeRoot, "socket": &p.Socket,
	}) {
		return p, errors.New("invalid policy value types")
	}
	if p.Version == 2 {
		payload, valid := objectFields(f["payload"], "station_profile")
		if !valid || len(payload) != 1 {
			return p, errors.New("invalid station payload fields")
		}
		profile, valid := objectFields(payload["station_profile"], "v", "kind", "executable", "executable_sha256", "static_release_sha256", "gateway", "gateway_cert_sha256", "dialect", "model", "max_tokens")
		var typed payloadlaunch.Profile
		if !valid || len(profile) != 10 || !decodeFields(profile, map[string]any{
			"v": &typed.Version, "kind": &typed.Kind, "executable": &typed.Executable, "executable_sha256": &typed.ExecutableSHA256,
			"static_release_sha256": &typed.StaticReleaseSHA256, "gateway": &typed.Gateway, "gateway_cert_sha256": &typed.GatewayCertSHA256,
			"dialect": &typed.Dialect, "model": &typed.Model, "max_tokens": &typed.MaxTokens,
		}) {
			return p, errors.New("invalid station profile fields")
		}
		p.Payload.StationProfile = &typed
	} else {
		payload, valid := objectFields(f["payload"], "path", "sha256", "argv")
		if !valid || len(payload) != 3 || !decodeFields(payload, map[string]any{"path": &p.Payload.Path, "sha256": &p.Payload.SHA256, "argv": &p.Payload.Argv}) {
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
	if err := p.validate(); err != nil {
		return p, err
	}
	return p, rejectHostEgress(p, hostAddresses)
}

// hostAddresses lists this host's own interface addresses at policy load.
var hostAddresses = func() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if prefix, perr := netip.ParsePrefix(a.String()); perr == nil {
			out = append(out, prefix.Addr().Unmap())
		}
	}
	return out, nil
}

// rejectHostEgress refuses an egress address owned by this host, which would
// reach host listeners through the shared network namespace (matrix row 14).
// Only the exact station gateway rule is exempt. It runs at policy load, not
// in validate, so a later address change cannot strand destroy or stop.
func rejectHostEgress(p policy, own func() ([]netip.Addr, error)) error {
	addrs, err := own()
	if err != nil {
		return errors.New("host address inventory unavailable")
	}
	gateway, exempt := stationGatewayRule(p)
	for _, rule := range p.Egress {
		if exempt && rule == gateway {
			continue
		}
		for _, a := range addrs {
			if a.String() == rule.Addr {
				return errors.New("invalid egress rule: host address")
			}
		}
	}
	return nil
}

func stationGatewayRule(p policy) (egressRule, bool) {
	if p.Version != 2 || p.Payload.StationProfile == nil {
		return egressRule{}, false
	}
	gateway, err := netip.ParseAddrPort(p.Payload.StationProfile.Gateway)
	if err != nil {
		return egressRule{}, false
	}
	return egressRule{Addr: gateway.Addr().String(), Port: gateway.Port(), Proto: "tcp"}, true
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
	if p.Version == 2 {
		if p.Payload.StationProfile == nil || p.Payload.Path != "" || p.Payload.SHA256 != "" || p.Payload.Argv != nil {
			return errors.New("typed profile cannot contain literal launch options")
		}
		if _, err := payloadlaunch.EncodeProfile(*p.Payload.StationProfile); err != nil {
			return err
		}
		for _, c := range p.HomeRoot {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-", c) {
				return errors.New("invalid station home path")
			}
		}
	} else if p.Version != 0 || p.Payload.StationProfile != nil {
		return errors.New("unsupported policy profile")
	} else if !cleanAbsolutePath(p.Payload.Path) || !digestPattern.MatchString(p.Payload.SHA256) || len(p.Payload.Argv) == 0 || len(p.Payload.Argv) > 128 || p.Payload.Argv[0] != p.Payload.Path {
		return errors.New("invalid payload binding")
	}
	if p.payloadPath() == p.HomeRoot || strings.HasPrefix(p.payloadPath(), p.HomeRoot+"/") {
		return errors.New("payload inside writable home root")
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
	gateway, exempt := stationGatewayRule(p)
	if p.Version == 2 && !exempt {
		return errors.New("invalid station gateway")
	}
	seen, err := validateEgress(p.Egress, gateway, exempt)
	if err != nil {
		return err
	}
	if p.Version == 2 && !seen[gateway] {
		return errors.New("station gateway missing from egress policy")
	}
	return nil
}

// validateEgress also refuses loopback and link-local destinations: the slot
// shares the host network namespace, so such a rule opens host-local
// listeners (node RPC, resolver stub). The single exception is the exact
// station gateway addr:port, which may be the only loopback rule.
func validateEgress(rules []egressRule, gateway egressRule, exempt bool) (map[egressRule]bool, error) {
	if len(rules) > 256 {
		return nil, errors.New("invalid egress list")
	}
	seen := make(map[egressRule]bool)
	for _, rule := range rules {
		addr, err := netip.ParseAddr(rule.Addr)
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() || addr.String() != rule.Addr || rule.Port == 0 || (rule.Proto != "tcp" && rule.Proto != "udp") || seen[rule] {
			return nil, errors.New("invalid egress rule")
		}
		if (addr.IsLoopback() || addr.IsLinkLocalUnicast()) && !(exempt && rule == gateway) {
			return nil, errors.New("invalid egress rule: host-local address")
		}
		seen[rule] = true
	}
	return seen, nil
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
