package slotd

import (
	"errors"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	systemdRunPath = "/usr/bin/systemd-run"
	systemctlPath  = "/usr/bin/systemctl"
	nftPath        = "/usr/sbin/nft"
	// slotLauncherPath is the installed daemon binary. As the slot's ExecStart
	// it applies the abstract-socket and signal Landlock scope, then execs the
	// payload argv; it never runs a payload unconfined (T19 layer 2).
	slotLauncherPath = "/usr/libexec/swarma-slotd-demo"
	slotLaunchFlag   = "--slot-launch"
	// walletSocketDir holds only the agent wallet's action socket. The slot
	// sees it through a read-only DIRECTORY bind, so a wallet restart that
	// recreates the socket inode stays reachable (T19 layer 1).
	walletSocketDir = "/run/swarma-wallet"
)

// slotTemporaryFileSystems replaces every tree that can hold another
// service's pathname socket with an empty read-only tmpfs. /dev/shm is listed
// because PrivateDevices= binds the host's /dev/shm into the private /dev.
var slotTemporaryFileSystems = []string{"/run:ro", "/var:ro", "/dev/shm:ro"}

// slotHardening is T19 layer 3: no netlink/packet sockets, private SysV/POSIX
// IPC, no new namespaces, and host processes invisible in the slot's /proc.
var slotHardening = []string{"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "PrivateIPC=yes", "RestrictNamespaces=yes", "ProtectProc=invisible", "ProcSubset=pid"}

// slotReadOnlyBinds are the only host paths re-exposed below the hidden
// trees: the wallet socket directory, the payload executable and, for a
// station, its read-only inputs and static release. Writable binds stay in
// BindPaths (home and station journal).
// The wallet entry carries systemd's "-" (ignore if absent): a host without
// the wallet still starts slots, which then have no AF_UNIX endpoint at all.
func slotReadOnlyBinds(p policy, station *payloadlaunch.Manifest) []string {
	binds := []string{"-" + walletSocketDir, p.payloadPath()}
	if station != nil {
		paths, err := payloadlaunch.PathsFor(station.UID)
		if err == nil {
			binds = append(binds, paths.Inputs, path.Dir(paths.StaticManifest))
		}
	}
	return binds
}

type toolInvocation struct {
	Path  string
	Args  []string
	Stdin []byte
}

// Policy permits at most three decimal places. A milli-percent is exactly ten
// microseconds of quota per second; no floating-point rounding is involved.
func cpuQuotaMicros(value string) (int64, error) {
	if !cpuPattern.MatchString(value) {
		return 0, errors.New("invalid CPU quota")
	}
	whole, fraction, _ := strings.Cut(strings.TrimSuffix(value, "%"), ".")
	n, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	fraction += strings.Repeat("0", 3-len(fraction))
	f, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return 0, err
	}
	result := (n*1000 + f) * 10
	if result <= 0 {
		return 0, errors.New("invalid CPU quota")
	}
	return result, nil
}

// startInvocation constructs a transient-service vector only. Production first
// verifies payload bytes/NFT and adds its mandatory ExecStartPre kernel fence.
func startInvocation(p policy, slot string, current record, now time.Time, station ...payloadlaunch.Manifest) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	if _, code := planTransition(request{Op: "start"}, &current, p.payloadDigest(), now); code != "" {
		return toolInvocation{}, errors.New(string(code))
	}
	argv := p.Payload.Argv
	binds := quoteSystemdWord(id.Home)
	var manifest *payloadlaunch.Manifest
	if p.Version == 2 {
		if len(station) != 1 {
			return toolInvocation{}, payloadlaunch.ErrMissing
		}
		m := station[0]
		n, _ := strconv.ParseUint(slot, 10, 32)
		if m.Slot != uint32(n) || m.UID != id.UID || m.GID != id.UID || m.Bootstrap.SHA256 != current.BootstrapSHA256 || m.NotAfter != current.NotAfter.Format(time.RFC3339) {
			return toolInvocation{}, payloadlaunch.ErrBinding
		}
		if err = payloadlaunch.CheckProfile(m, *p.Payload.StationProfile); err != nil {
			return toolInvocation{}, err
		}
		argv, err = payloadlaunch.Argv(m)
		if err != nil {
			return toolInvocation{}, err
		}
		binds += " " + quoteSystemdWord(m.Journal.Path)
		manifest = &m
	} else if len(station) != 0 {
		return toolInvocation{}, payloadlaunch.ErrBinding
	}
	remaining := current.NotAfter.Sub(now)
	// Use integer microseconds, rounded down, so this limit never rounds past
	// the remaining deadline. The service's wall-clock expiry is also required.
	properties := []string{
		"Type=exec", "User=" + id.Name, "Group=" + id.Name,
		"WorkingDirectory=" + id.Home,
		"CPUQuota=" + p.Caps.CPUQuota, "MemoryMax=" + p.Caps.MemoryMax,
		"TasksMax=" + strconv.FormatUint(uint64(p.Caps.TasksMax), 10),
		"RuntimeMaxSec=" + strconv.FormatInt(remaining.Microseconds(), 10) + "us",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=tmpfs",
		"BindPaths=" + binds,
		"PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
		"ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
		"LockPersonality=yes", "CapabilityBoundingSet=",
		"StandardInput=null", "StandardOutput=journal", "StandardError=journal",
	}
	for _, tmpfs := range slotTemporaryFileSystems {
		properties = append(properties, "TemporaryFileSystem="+tmpfs)
	}
	var readOnly []string
	for _, bind := range slotReadOnlyBinds(p, manifest) {
		readOnly = append(readOnly, quoteSystemdWord(bind))
	}
	properties = append(properties, "BindReadOnlyPaths="+strings.Join(readOnly, " "))
	properties = append(properties, slotHardening...)
	if p.Version == 2 {
		properties = append(properties, "SupplementaryGroups=", "Environment=", "EnvironmentFile=", "PassEnvironment=")
	}
	properties = append(properties, systemdAddressProperties(p)...)
	args := []string{"--system", "--quiet", "--no-ask-password", "--unit=" + id.Unit, "--expand-environment=no"}
	for _, property := range properties {
		args = append(args, "--property="+property)
	}
	args = append(args, "--", slotLauncherPath, slotLaunchFlag)
	args = append(args, argv...)
	return toolInvocation{Path: systemdRunPath, Args: args}, nil
}

// BindPaths is parsed as a systemd word even though no shell is involved.
func quoteSystemdWord(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func stopInvocation(p policy, slot string) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	return toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "stop", "--", id.Unit}}, nil
}

func deleteNFTInvocation(p policy, slot string) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	return toolInvocation{Path: nftPath, Args: []string{"delete", "table", "inet", id.Table}}, nil
}
