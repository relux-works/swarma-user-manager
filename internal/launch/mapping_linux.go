//go:build linux

package launch

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

const (
	launchMappingsFormat = "station-launch-mappings/1"
	launchMappingFormat  = "station-launch-mapping/1"
)

var gatewayGeneration = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type launchMappings struct {
	Format string   `json:"format"`
	Mapped []string `json:"mapped"`
}

type launchMapping struct {
	Format             string `json:"format"`
	ExecutorID         string `json:"executor_id"`
	ExecutorSHA256     string `json:"executor_sha256"`
	Kind               string `json:"kind"`
	GatewaySocket      string `json:"gateway_socket"`
	BaseURL            string `json:"base_url"`
	CredentialVariable string `json:"credential_variable"`
	Placeholder        string `json:"placeholder"`
	Network            string `json:"network"`
}

func mappingMetadata(file *os.File, owner uint32, directory bool) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		return fail("launch_mapping_invalid")
	}
	return checkMappingStat(stat, owner, directory)
}

func checkMappingStat(stat unix.Stat_t, owner uint32, directory bool) error {
	if stat.Uid != owner || stat.Gid != owner {
		return fail("launch_mapping_invalid")
	}
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0755 {
			return fail("launch_mapping_invalid")
		}
	} else if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0644 || stat.Nlink != 1 {
		return fail("launch_mapping_invalid")
	}
	return nil
}

func mappingOpenError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fail("launch_mapping_invalid")
	}
	return fail("launch_mapping_unavailable")
}

func readMappingFile(directory *os.File, name string, owner uint32) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, mappingOpenError(err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := mappingMetadata(file, owner, false); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, manager.MaxRequest+1))
	if err != nil || file.Close() != nil {
		return nil, fail("launch_mapping_unavailable")
	}
	if len(data) > manager.MaxRequest {
		return nil, fail("launch_mapping_invalid")
	}
	return data, nil
}

func (l Launcher) launchMapping(executor approvedExecutor) (*launchMapping, error) {
	store := l.Store
	etc, err := manager.ProtectedDir(filepath.Join(store.root, "etc"), store.owner, store.anchor)
	if err != nil {
		return nil, fail("launch_mapping_unavailable")
	}
	defer etc.Close()
	fd, err := unix.Openat(int(etc.Fd()), "launch-mappings", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, mappingOpenError(err)
	}
	directory := os.NewFile(uintptr(fd), "launch-mappings")
	defer directory.Close()
	if err := mappingMetadata(directory, store.owner, true); err != nil {
		return nil, err
	}
	var indexStat unix.Stat_t
	if err := unix.Fstatat(fd, "index.json", &indexStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil, nil
	} else if err != nil {
		return nil, fail("launch_mapping_unavailable")
	}
	data, err := readMappingFile(directory, "index.json", store.owner)
	if err != nil {
		return nil, err
	}
	var index launchMappings
	if manager.Strict(data, &index) != nil || index.Format != launchMappingsFormat || index.Mapped == nil {
		return nil, fail("launch_mapping_invalid")
	}
	listed := false
	for position, id := range index.Mapped {
		if !executorPattern.MatchString(id) || position > 0 && index.Mapped[position-1] >= id {
			return nil, fail("launch_mapping_invalid")
		}
		if id == executor.ID {
			listed = true
		}
	}
	if !listed {
		return nil, nil
	}
	data, err = readMappingFile(directory, executor.ID+".json", store.owner)
	if err != nil {
		return nil, err
	}
	var mapping launchMapping
	if manager.Strict(data, &mapping) != nil || !mapping.valid(store.root, executor.ID) {
		return nil, fail("launch_mapping_invalid")
	}
	if mapping.ExecutorSHA256 != executor.Digest {
		return nil, fail("launch_mapping_digest_mismatch")
	}
	if err := l.gatewaySocket(mapping.GatewaySocket); err != nil {
		return nil, err
	}
	return &mapping, nil
}

func (mapping launchMapping) valid(root, executorID string) bool {
	if mapping.Format != launchMappingFormat || mapping.ExecutorID != executorID || !manager.HashOK(mapping.ExecutorSHA256) || mapping.Kind != "claude-gateway" && !labMappingValid(mapping) || mapping.BaseURL != "http://api.anthropic.com" || mapping.CredentialVariable != "CLAUDE_CODE_OAUTH_TOKEN" && !labMappingValid(mapping) || mapping.Placeholder != "ssh-placeholder" || mapping.Network != "unix-only" {
		return false
	}
	prefix := filepath.Join(root, "run/credential-gateway") + "/"
	generation := strings.TrimSuffix(strings.TrimPrefix(mapping.GatewaySocket, prefix), "/gateway.sock")
	return gatewayGeneration.MatchString(generation) && mapping.GatewaySocket == prefix+generation+"/gateway.sock"
}

func (l Launcher) gatewaySocket(path string) error {
	root, err := manager.ProtectedDir(l.Store.root, l.Store.owner, l.Store.anchor)
	if err != nil {
		return fail("launch_mapping_unavailable")
	}
	defer root.Close()
	directory := root
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(path), l.Store.root+"/"), "/") {
		fd, err := unix.Openat(int(directory.Fd()), component, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if directory != root {
			directory.Close()
		}
		if err != nil {
			return fail("launch_mapping_unavailable")
		}
		directory = os.NewFile(uintptr(fd), component)
	}
	defer directory.Close()
	var stat unix.Stat_t
	if unix.Fstatat(int(directory.Fd()), "gateway.sock", &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fail("launch_mapping_unavailable")
	}
	return nil
}

func (mapping launchMapping) environment() []string {
	return mappingEnvironment(mapping, []string{
		"ANTHROPIC_UNIX_SOCKET=" + mapping.GatewaySocket,
		"ANTHROPIC_BASE_URL=http://api.anthropic.com",
		"CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_UPDATES=1",
	})
}
