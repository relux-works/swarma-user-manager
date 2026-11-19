//go:build linux

package launch

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Claim: each bounded source plant is applied exactly once and must fail its
// named product assertion while retaining the named valid control. Compilation,
// setup failures, timeouts and unrelated failures do not kill a plant.
func TestLaunchMappingPlants(t *testing.T) {
	type plant struct {
		name, file, before, after, test, assertion, control string
		looseJSON                                           bool
	}
	plants := []plant{
		{name: "fstat-error", file: "mapping_linux.go", before: "if unix.Fstat(int(file.Fd()), &stat) != nil {\n\t\treturn fail(\"launch_mapping_invalid\")", after: "if unix.Fstat(int(file.Fd()), &stat) != nil {\n\t\treturn nil", test: "TestLaunchMappingMetadata", assertion: "failed fstat admitted"},
		{name: "owner", file: "mapping_linux.go", before: "stat.Uid != owner || stat.Gid != owner", after: "stat.Gid != owner", test: "TestLaunchMappingMetadata/false-owner", assertion: "unsafe mapping metadata admitted"},
		{name: "group", file: "mapping_linux.go", before: "stat.Uid != owner || stat.Gid != owner", after: "stat.Uid != owner", test: "TestLaunchMappingMetadata/false-group", assertion: "unsafe mapping metadata admitted"},
		{name: "parent-owner", file: "mapping_linux.go", before: "stat.Uid != owner || stat.Gid != owner", after: "!directory && stat.Uid != owner || stat.Gid != owner", test: "TestLaunchMappingMetadata/true-owner", assertion: "unsafe mapping metadata admitted"},
		{name: "parent-group", file: "mapping_linux.go", before: "stat.Uid != owner || stat.Gid != owner", after: "stat.Uid != owner || !directory && stat.Gid != owner", test: "TestLaunchMappingMetadata/true-group", assertion: "unsafe mapping metadata admitted"},
		{name: "parent-type", file: "mapping_linux.go", before: "stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0755", after: "stat.Mode&07777 != 0755", test: "TestLaunchMappingMetadata/true-type", assertion: "unsafe mapping metadata admitted"},
		{name: "parent-mode", file: "mapping_linux.go", before: "stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&07777 != 0755", after: "stat.Mode&unix.S_IFMT != unix.S_IFDIR", test: "TestLaunchMappingGates/parent-mode", assertion: "want refusal launch_mapping_invalid"},
		{name: "file-type", file: "mapping_linux.go", before: "stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0644", after: "stat.Mode&07777 != 0644", test: "TestLaunchMappingMetadata/false-type", assertion: "unsafe mapping metadata admitted"},
		{name: "file-mode", file: "mapping_linux.go", before: "stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0644", after: "stat.Mode&unix.S_IFMT != unix.S_IFREG", test: "TestLaunchMappingGates/index.json-mode", assertion: "want refusal launch_mapping_invalid"},
		{name: "single-link", file: "mapping_linux.go", before: " || stat.Nlink != 1", after: "", test: "TestLaunchMappingGates/index.json-hardlink", assertion: "want refusal launch_mapping_invalid"},
		{name: "file-no-follow", file: "mapping_linux.go", before: "unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK", after: "unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK", test: "TestLaunchMappingGates/index.json-symlink", assertion: "want refusal launch_mapping_invalid"},
		{name: "parent-no-follow", file: "mapping_linux.go", before: "unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW", after: "unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC", test: "TestLaunchMappingGates/parent-link", assertion: "want refusal launch_mapping_invalid"},
		{name: "bounded-file", file: "mapping_linux.go", before: "if len(data) > manager.MaxRequest {", after: "if false {", test: "TestLaunchMappingReadBound", assertion: "oversized mapping read admitted"},
		{name: "missing-mapping", file: "mapping_linux.go", before: "data, err = readMappingFile(directory, executor.ID+\".json\", store.owner)\n\tif err != nil {\n\t\treturn nil, err", after: "data, err = readMappingFile(directory, executor.ID+\".json\", store.owner)\n\tif err != nil {\n\t\treturn nil, nil", test: "TestLaunchMappingGates/listed-missing-mapping", assertion: "want refusal launch_mapping_unavailable"},
		{name: "absent-directory", file: "mapping_linux.go", before: "if errors.Is(err, unix.ENOENT) {\n\t\treturn nil, nil", after: "if errors.Is(err, unix.ENOENT) {\n\t\treturn nil, fail(\"launch_mapping_unavailable\")", test: "TestLaunchMappingGates/missing-directory", assertion: "mapping control refused"},
		{name: "absent-index", file: "mapping_linux.go", before: "if err := unix.Fstatat(fd, \"index.json\", &indexStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {\n\t\treturn nil, nil", after: "if err := unix.Fstatat(fd, \"index.json\", &indexStat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {\n\t\treturn nil, fail(\"launch_mapping_unavailable\")", test: "TestLaunchMappingGates/missing-index", assertion: "mapping control refused"},
		{name: "empty-index", file: "mapping_linux.go", before: "if !listed {", after: "if !listed && len(index.Mapped) > 0 {", test: "TestLaunchMappingGates/empty-index", assertion: "mapping environment differs from fixed contract"},
		{name: "index-closed-ccj", file: "mapping_linux.go", before: "manager.Strict(data, &index)", after: "json.Unmarshal(data, &index)", test: "TestLaunchMappingGates/index.json-unknown", assertion: "want refusal launch_mapping_invalid", looseJSON: true},
		{name: "mapping-closed-ccj", file: "mapping_linux.go", before: "manager.Strict(data, &mapping)", after: "json.Unmarshal(data, &mapping)", test: "TestLaunchMappingGates/m0-executor.json-unknown", assertion: "want refusal launch_mapping_invalid", looseJSON: true},
		{name: "index-format", file: "mapping_linux.go", before: "index.Format != launchMappingsFormat", after: "false", test: "TestLaunchMappingClosedValues/index-format", assertion: "want refusal launch_mapping_invalid"},
		{name: "index-null", file: "mapping_linux.go", before: "index.Mapped == nil", after: "false", test: "TestLaunchMappingClosedValues/index-null", assertion: "want refusal launch_mapping_invalid"},
		{name: "index-id", file: "mapping_linux.go", before: "!executorPattern.MatchString(id)", after: "false", test: "TestLaunchMappingClosedValues/index-invalid-id", assertion: "want refusal launch_mapping_invalid"},
		{name: "index-sorted-unique", file: "mapping_linux.go", before: "index.Mapped[position-1] >= id", after: "index.Mapped[position-1] > id", test: "TestLaunchMappingClosedValues/index-duplicate", assertion: "want refusal launch_mapping_invalid"},
		{name: "index-sorted", file: "mapping_linux.go", before: "index.Mapped[position-1] >= id", after: "index.Mapped[position-1] == id", test: "TestLaunchMappingClosedValues/index-unsorted", assertion: "want refusal launch_mapping_invalid"},
		{name: "unlisted-selection", file: "mapping_linux.go", before: "if id == executor.ID {", after: "if true {", test: "TestLaunchMappingGates/unlisted", assertion: "mapping control refused"},
		{name: "digest-binding", file: "mapping_linux.go", before: "if mapping.ExecutorSHA256 != executor.Digest {", after: "if false {", test: "TestLaunchMappingGates/digest", assertion: "want refusal launch_mapping_digest_mismatch"},
		{name: "generation-grammar", file: "mapping_linux.go", before: "gatewayGeneration.MatchString(generation) &&", after: "true &&", test: "TestLaunchMappingClosedValues/generation-", assertion: "invalid generation admitted"},
		{name: "socket-root-and-suffix", file: "mapping_linux.go", before: "return gatewayGeneration.MatchString(generation) && mapping.GatewaySocket == prefix+generation+\"/gateway.sock\"", after: "return gatewayGeneration.MatchString(generation) || gatewayGeneration.MatchString(filepath.Base(filepath.Dir(mapping.GatewaySocket)))", test: "TestLaunchMappingClosedValues/socket-root-and-suffix", assertion: "invalid socket path admitted"},
		{name: "socket-presence", file: "mapping_linux.go", before: "unix.Fstatat(int(directory.Fd()), \"gateway.sock\", &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||", after: "unix.Fstatat(int(directory.Fd()), \"gateway.sock\", &stat, unix.AT_SYMLINK_NOFOLLOW) == nil &&", test: "TestLaunchMappingGates/missing-socket", assertion: "want refusal launch_mapping_unavailable"},
		{name: "socket-type", file: "mapping_linux.go", before: "stat.Mode&unix.S_IFMT != unix.S_IFSOCK", after: "false", test: "TestLaunchMappingGates/non-socket", assertion: "want refusal launch_mapping_unavailable"},
		{name: "socket-no-follow", file: "mapping_linux.go", before: "\"gateway.sock\", &stat, unix.AT_SYMLINK_NOFOLLOW", after: "\"gateway.sock\", &stat, 0", test: "TestLaunchMappingGates/socket-link", assertion: "want refusal launch_mapping_unavailable"},
		{name: "socket-parent-no-follow", file: "mapping_linux.go", before: "unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW", after: "unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC", test: "TestLaunchMappingGates/socket-parent-link", assertion: "want refusal launch_mapping_unavailable"},
		{name: "inherited-environment", file: "launcher_linux.go", before: "env = append(env, mapping.environment()...)", after: "env = append(env, mapping.environment()...)\n\t\tenv = append(env, os.Environ()...)", test: "TestLaunchMappingEnvironmentAndOrdering/valid", assertion: "worker environment is not the exact fixed set", control: "TestLaunchMappingUnlistedBytes/unlisted"},
		{name: "missing-confinement", file: "launcher_linux.go", before: "d.Confine == nil || d.Confine() != nil", after: "d.Confine != nil && d.Confine() != nil", test: "TestLaunchMappingEnvironmentAndOrdering/missing-confinement", assertion: "want refusal launch_confinement_unavailable"},
		{name: "failed-confinement", file: "launcher_linux.go", before: "d.Confine == nil || d.Confine() != nil", after: "d.Confine == nil || d.Confine() != nil && false", test: "TestLaunchMappingEnvironmentAndOrdering/failed-confinement", assertion: "want refusal launch_confinement_unavailable"},
		{name: "filter-load-error", file: "confinement_linux.go", before: "errno != 0 || result != 0", after: "errno != 0 && false || result != 0 && false", test: "TestLaunchConfinementProcesses/load-failure", assertion: "filter load failure did not refuse"},
		{name: "production-wiring", file: "launcher_linux.go", before: "Confine: ConfineUnixOnly", after: "Confine: nil", test: "TestLaunchConfinementFilter/production", assertion: "production confinement is not native"},
		{name: "drop-before-confinement", file: "launcher_linux.go", before: "if e := d.Drop(uint32(account.UID), uint32(account.GID)); e != nil {", after: "if mapping != nil && d.Confine != nil { _ = d.Confine() }\n\tif e := d.Drop(uint32(account.UID), uint32(account.GID)); e != nil {", test: "TestLaunchMappingEnvironmentAndOrdering/valid", assertion: "confinement before drop or committed start"},
		{name: "receipt-bytes", file: "receipt.go", before: "`json:\"start_time\"`", after: "`json:\"changed_start_time\"`", test: "TestLaunchMappingEnvironmentAndOrdering/valid", assertion: "receipt bytes changed"},
		{name: "launch-op-closed", file: "request.go", before: "if len(m) != len(names) {", after: "if len(m) < len(names) {", test: "TestLaunchMappingEnvironmentAndOrdering/input-environment", assertion: "want refusal request_invalid"},
		{name: "no-new-privileges", file: "confinement_linux.go", before: "if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {", after: "if false {", test: "TestLaunchConfinementProcesses/install", assertion: "native filter load"},
		{name: "thread-sync", file: "confinement_linux.go", before: "unix.SECCOMP_FILTER_FLAG_TSYNC", after: "0", test: "TestLaunchConfinementProcesses/install", assertion: "native peer thread not confined"},
		{name: "non-unix-family", file: "confinement_linux.go", before: "K: unix.AF_UNIX, Jt: 1},\n\t\t{Code: unix.BPF_RET | unix.BPF_K, K: deny}", after: "K: unix.AF_UNIX, Jt: 1},\n\t\t{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}", test: "TestLaunchConfinementFilter/family-", assertion: "non-Unix family allowed"},
		{name: "socketpair-family", file: "confinement_linux.go", before: "K: uint32(unix.SYS_SOCKETPAIR), Jt: 1", after: "K: uint32(unix.SYS_SOCKETPAIR), Jt: 0", test: "TestLaunchConfinementFilter/family-", assertion: "non-Unix family allowed"},
		{name: "compat-abi", file: "confinement_linux.go", before: "K: unix.SECCOMP_RET_KILL_PROCESS", after: "K: unix.SECCOMP_RET_ALLOW", test: "TestLaunchConfinementFilter/compat-socketcall", assertion: "compat socketcall ABI allowed"},
		{name: "x32-abi", file: "confinement_linux.go", before: "K: 0x40000000, Jf: 1", after: "K: 0x20000000, Jf: 1", test: "TestLaunchConfinementFilter/x32", assertion: "forbidden syscall allowed"},
	}
	for _, field := range []struct{ name, expression string }{
		{"format", "mapping.Format != launchMappingFormat"}, {"executor_id", "mapping.ExecutorID != executorID"}, {"executor_sha256", "!manager.HashOK(mapping.ExecutorSHA256)"},
		{"kind", "mapping.Kind != \"claude-gateway\""}, {"base_url", "mapping.BaseURL != \"http://api.anthropic.com\""},
		{"credential_variable", "mapping.CredentialVariable != \"CLAUDE_CODE_OAUTH_TOKEN\""}, {"placeholder", "mapping.Placeholder != \"ssh-placeholder\""}, {"network", "mapping.Network != \"unix-only\""},
	} {
		test := "TestLaunchMappingClosedValues/" + field.name
		assertion := "want refusal launch_mapping_invalid"
		if field.name == "executor_sha256" {
			test = "TestLaunchMappingClosedValues/executor_sha256"
			assertion = "want refusal launch_mapping_invalid"
		}
		plants = append(plants, plant{name: "closed-" + field.name, file: "mapping_linux.go", before: field.expression, after: "false", test: test, assertion: assertion})
	}
	for _, variable := range []string{
		"ANTHROPIC_UNIX_SOCKET", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "DISABLE_AUTOUPDATER", "DISABLE_UPDATES",
	} {
		plants = append(plants, plant{name: "fixed-" + variable, file: "mapping_linux.go", before: "\"" + variable + "=", after: "\"ALTERED_" + variable + "=", test: "TestLaunchMappingEnvironmentAndOrdering/valid", assertion: "worker environment is not the exact fixed set", control: "TestLaunchMappingUnlistedBytes/unlisted"})
	}
	for _, name := range []string{"SETUP", "ENTER", "REGISTER"} {
		plants = append(plants, plant{name: "io-uring-" + name, file: "confinement_linux.go", before: "uint32(unix.SYS_IO_URING_" + name + ")", after: "uint32(unix.SYS_GETUID)", test: "TestLaunchConfinementFilter/io-uring-" + strings.ToLower(name), assertion: "forbidden syscall allowed"})
	}
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	run := func(overlay string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		arguments := []string{"test", "-p", "1", "-count=1", "-v", "-timeout=90s", "-run", "^TestLaunch(Mapping(Gates|ClosedValues|Metadata|ReadBound|EnvironmentAndOrdering|UnlistedBytes)|Confinement(Filter|Processes))$"}
		if overlay != "" {
			arguments = append(arguments, "-overlay", overlay)
		}
		arguments = append(arguments, ".")
		command := exec.CommandContext(ctx, "go", arguments...)
		command.Dir = directory
		output, err := command.CombinedOutput()
		return string(output), err
	}
	controlOutput, err := run("")
	if err != nil {
		t.Fatalf("plant baseline failed: %v %s", err, controlOutput)
	}
	for _, mutation := range plants {
		t.Run(mutation.name, func(t *testing.T) {
			sourcePath := filepath.Join(directory, mutation.file)
			source, err := os.ReadFile(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(source), mutation.before) != 1 {
				t.Fatal("plant predicate is not unique")
			}
			altered := strings.Replace(string(source), mutation.before, mutation.after, 1)
			if mutation.looseJSON {
				altered = strings.Replace(altered, "import (", "import (\n\"encoding/json\"", 1)
			}
			scratch := t.TempDir()
			mutantPath := filepath.Join(scratch, mutation.file)
			if err := os.WriteFile(mutantPath, []byte(altered), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{sourcePath: mutantPath}})
			if err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(scratch, "overlay.json")
			if err := os.WriteFile(overlay, data, 0600); err != nil {
				t.Fatal(err)
			}
			red, err := run(overlay)
			exit, ok := err.(*exec.ExitError)
			validControl := mutation.control
			if validControl == "" {
				validControl = "TestLaunchMappingGates/valid"
			}
			if !ok || exit.ExitCode() != 1 || !strings.Contains(red, "--- FAIL: "+mutation.test) || !strings.Contains(red, mutation.assertion) || !strings.Contains(red, "--- PASS: "+validControl) {
				t.Fatalf("plant survived or failed outside its claim: %v\n%s", err, red)
			}
			observedFailure := ""
			for _, line := range strings.Split(red, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "--- FAIL: "+mutation.test) {
					observedFailure = strings.Fields(line)[2]
					break
				}
			}
			t.Logf("plant=%s narrowed_to=%s killed_by=%s exit=1 control=%s:PASS", mutation.name, mutation.assertion, observedFailure, validControl)
		})
	}
}
