//go:build linux

package linuxos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// FilesNSSRuntime is the status-aware files implementation. The later reviewed
// Environment supplies its loader resolver and complete configuration closure.
// They are capabilities, never fields decoded from a qualification record.
// Library is the actual reviewed object exporting _nss_files_* (modern glibc
// integrates it into libc; an obsolete libnss_files stub alone cannot qualify).
type FilesNSSRuntime struct {
	Collector, Library ProtectedArtifact
	Resolver           ELFResolver
	Configuration      []ProtectedArtifact
}

var _ NSSRuntime = FilesNSSRuntime{}

func onlyFiles(names []string) bool { return reflect.DeepEqual(names, []string{"files"}) }
func (r FilesNSSRuntime) CaptureModules(ctx context.Context, names []string, l Limits) ([]NSSModule, error) {
	if !onlyFiles(names) {
		return nil, refusal("directory_unknown", "module_unsupported_or_unqualified", nil)
	}
	_, impl, e := CaptureImplementationClosure(ctx, []ProtectedArtifact{r.Collector, r.Library}, r.Resolver, l)
	if e != nil {
		return nil, e
	}
	_, config, e := CaptureConfigurationClosure(ctx, r.Configuration, l)
	if e != nil {
		return nil, e
	}
	return []NSSModule{{Name: "files", ImplementationDigest: impl, ConfigurationDigest: config, UIDRanges: []IDInterval{}, GIDRanges: []IDInterval{}}}, nil
}
func openCaptured(ctx context.Context, a ProtectedArtifact) (f *os.File, err error) {
	captured, _, e := captureArtifact(ctx, a)
	if e != nil {
		return nil, e
	}
	f, e = child(a.Directory.f, a.Name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer func(handle *os.File) {
		if err != nil {
			err = errors.Join(err, handle.Close())
		}
	}(f)
	before, e := descriptorStat(f)
	if e != nil {
		return nil, e
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != a.Directory.owner || before.Gid != a.Directory.group || before.Nlink != 1 || before.Mode&0022 != 0 {
		return nil, refusal("directory_unknown", "collector_protection", nil)
	}
	if e = access(f); e != nil {
		return nil, e
	}
	b, e := readBounded(f, 8<<20)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	after, e := descriptorStat(f)
	if e != nil || !stableStat(before, after) || hex.EncodeToString(sum[:]) != captured.SHA256 {
		return nil, refusal("directory_unknown", "collector_changed", e)
	}
	if _, e = f.Seek(0, 0); e != nil {
		return nil, e
	}
	return f, nil
}
func (r FilesNSSRuntime) Enumerate(ctx context.Context, names []string, l Limits) (out NSSDatabases, err error) {
	if !onlyFiles(names) {
		return nil, refusal("directory_unknown", "module_unsupported_or_unqualified", nil)
	}
	return enumerateNSS(ctx, r.Collector, []ProtectedArtifact{r.Library}, l)
}

// enumerateNSS holds the executable and each reviewed module descriptor through
// subprocess completion. Only the two fixed module layouts are accepted. The
// two-module form is an additional diagnostic agreement view, not evidence of
// systemd provider completion; public SystemdNSSRuntime refuses that selection.
func enumerateNSS(ctx context.Context, collector ProtectedArtifact, libraries []ProtectedArtifact, l Limits) (out NSSDatabases, err error) {
	if len(libraries) != 1 && len(libraries) != 2 {
		return nil, refusal("directory_unknown", "collector_modules", nil)
	}
	c, cancel, e := budget(ctx, l)
	if e != nil {
		return nil, e
	}
	defer cancel()
	program, e := openCaptured(c, collector)
	if e != nil {
		return nil, e
	}
	defer closed(program, &err)
	handles := []*os.File{program}
	for _, artifact := range libraries {
		library, e := openCaptured(c, artifact)
		if e != nil {
			return nil, e
		}
		defer closed(library, &err)
		handles = append(handles, library)
	}
	// Held descriptors bind execution/dlopen to inspected objects. The caller's
	// maintained exclusion also protects their loader/configuration dependencies.
	args := []string{"/proc/self/fd/4", strconv.Itoa(l.Entries)}
	if len(libraries) == 2 {
		args = []string{"--files-systemd", strconv.Itoa(l.Entries), "/proc/self/fd/4", "/proc/self/fd/5"}
	}
	cmd := exec.CommandContext(c, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = handles
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	var output directoryOutput
	cmd.Stdout = &output
	if e = cmd.Run(); e != nil {
		return nil, refusal("directory_unknown", "nss_collector", e)
	}
	if e = c.Err(); e != nil {
		return nil, e
	}
	var snapshot struct {
		Passwd *string `json:"passwd"`
		Group  *string `json:"group"`
		Shadow *string `json:"shadow"`
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&snapshot); e != nil || snapshot.Passwd == nil || snapshot.Group == nil || snapshot.Shadow == nil {
		return nil, refusal("directory_unknown", "collector_format", nil)
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, refusal("directory_unknown", "collector_trailing", nil)
	}
	out = NSSDatabases{"passwd": []byte(*snapshot.Passwd), "group": []byte(*snapshot.Group), "shadow": []byte(*snapshot.Shadow)}
	if e = validateDirectoryDatabases(out, l.Entries, true); e != nil {
		return nil, e
	}
	return out, nil
}

type directoryOutput struct{ bytes.Buffer }

func (b *directoryOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, refusal("directory_unknown", "collector_output_limit", nil)
	}
	return b.Buffer.Write(p)
}
