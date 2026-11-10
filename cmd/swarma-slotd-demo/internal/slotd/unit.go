package slotd

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	systemdRunPath = "/usr/bin/systemd-run"
	systemctlPath  = "/usr/bin/systemctl"
	nftPath        = "/usr/sbin/nft"
)

type toolInvocation struct {
	Path  string
	Args  []string
	Stdin []byte
}

// startInvocation constructs a transient-service vector only. The caller must
// first verify the actual payload bytes and install both egress layers.
func startInvocation(p policy, slot string, current record, now time.Time) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	if _, code := planTransition(request{Op: "start"}, &current, p.Payload.SHA256, now); code != "" {
		return toolInvocation{}, errors.New(string(code))
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
		"BindPaths=" + quoteSystemdWord(id.Home),
		"PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes",
		"ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
		"LockPersonality=yes", "CapabilityBoundingSet=",
		"StandardInput=null", "StandardOutput=journal", "StandardError=journal",
	}
	properties = append(properties, systemdAddressProperties(p)...)
	args := []string{"--system", "--quiet", "--no-ask-password", "--unit=" + id.Unit, "--expand-environment=no"}
	for _, property := range properties {
		args = append(args, "--property="+property)
	}
	args = append(args, "--")
	args = append(args, p.Payload.Argv...)
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

func inspectUnitInvocation(p policy, slot string) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	return toolInvocation{Path: systemctlPath, Args: []string{"--system", "--no-ask-password", "show", "--property=LoadState,ActiveState,SubState,ControlGroup", "--", id.Unit}}, nil
}

func installNFTInvocation(p policy, slot string) (toolInvocation, error) {
	rules, err := nftRuleset(p, slot)
	if err != nil {
		return toolInvocation{}, err
	}
	return toolInvocation{Path: nftPath, Args: []string{"--file", "-"}, Stdin: rules}, nil
}

func deleteNFTInvocation(p policy, slot string) (toolInvocation, error) {
	id, err := p.identity(slot)
	if err != nil {
		return toolInvocation{}, err
	}
	return toolInvocation{Path: nftPath, Args: []string{"delete", "table", "inet", id.Table}}, nil
}
