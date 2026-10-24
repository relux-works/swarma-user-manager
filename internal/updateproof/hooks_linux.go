//go:build linux

package updateproof

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const HookConfigPath = "/opt/swarma/etc/update-evidence.json"
const RecorderPath = "/opt/swarma/lib/user-manager/update-evidence"

type HookConfig struct {
	Format    string
	Profile   Profile
	Baseline  Snapshot
	APT, DPKG Tool
}

func readRootFile(path string, limit int64) ([]byte, error) {
	d, e := openProtectedDir(filepath.Dir(path), 0, "/")
	if e != nil {
		return nil, e
	}
	defer d.Close()
	fd, e := unix.Openat(int(d.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrStore
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 || st.Size > limit {
		return nil, ErrStore
	}
	for _, n := range []string{"system.posix_acl_access", "security.capability"} {
		if _, e := unix.Fgetxattr(fd, n, nil); e != unix.ENODATA {
			return nil, ErrStore
		}
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrStore
	}
	return b, nil
}
func marker(boot string) error {
	b, e := readRootFile("/opt/swarma/lib/user-manager/maintenance.json", 1024)
	if e != nil {
		return ErrGap
	}
	var m struct {
		Format           string `json:"format"`
		BootID           string `json:"boot_id"`
		AdmissionStopped bool   `json:"admission_stopped"`
	}
	if closed(b, &m) != nil || m.Format != "station-maintenance/1" || m.BootID != boot || !m.AdmissionStopped {
		return ErrGap
	}
	return nil
}

type nativeCaller struct {
	token   string
	parent  int
	command []string
}

func caller(pid int, boot string, tool Tool) (nativeCaller, error) {
	stat := func() (string, []string, error) {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if e != nil {
			return "", nil, ErrGap
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			return "", nil, ErrGap
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 20 {
			return "", nil, ErrGap
		}
		return f[19], f, nil
	}
	start, fields, e := stat()
	if e != nil {
		return nativeCaller{}, e
	}
	p, e := strconv.Atoi(fields[1])
	if e != nil {
		return nativeCaller{}, ErrGap
	}
	name := fmt.Sprintf("/proc/%d", pid) // /proc stat uses syscall.Stat_t; read ownership through a descriptor instead.
	fd, e := unix.Open(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nativeCaller{}, ErrGap
	}
	var ps unix.Stat_t
	e = unix.Fstat(fd, &ps)
	unix.Close(fd)
	if e != nil || ps.Uid != 0 {
		return nativeCaller{}, ErrGap
	}
	exe, e := os.Readlink(name + "/exe")
	if e != nil || exe != tool.Path {
		return nativeCaller{}, ErrGap
	}
	f, e := pinnedTool(tool)
	if e != nil {
		return nativeCaller{}, e
	}
	defer f.Close()
	actual, e := os.Open(name + "/exe")
	if e != nil {
		return nativeCaller{}, ErrGap
	}
	defer actual.Close()
	a, _ := actual.Stat()
	b, _ := f.Stat()
	if a == nil || b == nil || !os.SameFile(a, b) {
		return nativeCaller{}, ErrGap
	}
	raw, e := os.ReadFile(name + "/cmdline")
	if e != nil || len(raw) > 1<<20 {
		return nativeCaller{}, ErrGap
	}
	again, _, e := stat()
	if e != nil || start != again {
		return nativeCaller{}, ErrGap
	}
	cwd, e := os.Readlink(name + "/cwd")
	if e != nil {
		return nativeCaller{}, ErrGap
	}
	commands := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	for n, arg := range commands {
		if strings.HasSuffix(arg, ".deb") && !filepath.IsAbs(arg) {
			commands[n] = filepath.Join(cwd, arg)
		}
	}
	token := Digest([]byte(fmt.Sprintf("%s:%d:%s:%s", boot, pid, start, tool.SHA256)))
	return nativeCaller{token, p, commands}, nil
}

// NativeHook accepts only fixed hook phases. It neither installs hooks nor
// creates a maintenance assertion: the qualified admission owner must already
// have stopped admission and established the pre-update containment interlock.
func NativeHook(ctx context.Context, phase string, parentPID int) (ScanResult, error) {
	allowed := map[string]bool{"apt-pre": true, "apt-post": true, "dpkg-pre": true, "dpkg-post": true, "boot-scan": true}
	if !allowed[phase] || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ScanResult{}, ErrGap
	}
	raw, e := readRootFile(HookConfigPath, 1<<20)
	if e != nil {
		return ScanResult{}, e
	}
	var cfg HookConfig
	if closed(raw, &cfg) != nil || cfg.Format != "station-update-hooks/1" || !cfg.Profile.Limits.valid() || !supportedNativeProfile(cfg.Profile) || !cfg.Baseline.valid(cfg.Profile.Limits) {
		return ScanResult{}, ErrStore
	}
	bootBytes, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(bootBytes))
	if e != nil || !tokenRE.MatchString(boot) {
		return ScanResult{}, ErrGap
	}
	r, e := OpenRecorder(RecorderPath, cfg.Profile.Limits)
	if e != nil {
		return ScanResult{}, e
	}
	defer r.Close()
	if phase == "boot-scan" {
		release, e := packageReadExclusion()
		if e != nil {
			return ScanResult{}, e
		}
		defer release()
		snapshot, e := captureNative(ctx, cfg, r, nil)
		if e != nil {
			return ScanResult{}, e
		}
		return r.Scan(ctx, snapshot)
	}
	if marker(boot) != nil {
		return ScanResult{}, ErrGap
	}
	tool := cfg.DPKG
	kind := "invocation"
	if strings.HasPrefix(phase, "apt-") {
		tool = cfg.APT
		kind = "aggregate"
	}
	self, e := caller(parentPID, boot, tool)
	if e != nil {
		return ScanResult{}, e
	}
	parent := ID{}
	if kind == "invocation" {
		if apt, e := caller(self.parent, boot, cfg.APT); e == nil {
			id, _, e := r.lookup(ctx, boot, "aggregate", apt.token)
			if e != nil {
				return ScanResult{}, e
			}
			parent = id
		}
	}
	var id ID
	var artifacts []Package
	if strings.HasSuffix(phase, "-post") {
		id, artifacts, e = r.lookup(ctx, boot, kind, self.token)
		if e != nil {
			return ScanResult{}, e
		}
	} else if kind == "invocation" {
		artifacts, e = captureArchives(ctx, cfg.Profile, self.command)
		if e != nil {
			return ScanResult{}, e
		}
	}
	captureArtifacts := artifacts
	if strings.HasSuffix(phase, "-pre") {
		captureArtifacts = nil
	}
	snapshot, e := captureNative(ctx, cfg, r, captureArtifacts)
	if e != nil {
		return ScanResult{}, e
	}
	if marker(boot) != nil {
		return ScanResult{}, ErrGap
	}
	if strings.HasSuffix(phase, "-pre") {
		_, e = r.BeginArtifacts(ctx, boot, kind, self.token, parent, snapshot, artifacts)
		return ScanResult{}, e
	}
	return ScanResult{}, r.ObservePost(ctx, id, snapshot)
}
func (r *Recorder) lookup(ctx context.Context, boot, kind, token string) (ID, []Package, error) {
	u, e := r.lock(ctx)
	if e != nil {
		return ID{}, nil, e
	}
	defer u()
	events, e := r.load()
	if e != nil {
		return ID{}, nil, e
	}
	for _, ev := range events {
		if ev.Phase == "begin" && ev.ID.Boot == boot && ev.ID.Kind == kind && ev.Token == token {
			return ev.ID, ev.Artifacts, nil
		}
	}
	return ID{}, nil, ErrGap
}
func (r *Recorder) endpoint(ctx context.Context, initial Snapshot) (Snapshot, error) {
	u, e := r.lock(ctx)
	if e != nil {
		return Snapshot{}, e
	}
	defer u()
	events, e := r.load()
	if e != nil {
		return Snapshot{}, e
	}
	if len(events) == 0 {
		return initial, nil
	}
	return events[len(events)-1].Snapshot, nil
}
func packageReadExclusion() (func(), error) {
	var files []*os.File
	release := func() {
		for i := len(files) - 1; i >= 0; i-- {
			files[i].Close()
		}
	}
	for _, name := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"} {
		fd, e := unix.Open(name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			release()
			return nil, ErrGap
		}
		f := os.NewFile(uintptr(fd), name)
		files = append(files, f)
		lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
		if unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lock) != nil {
			release()
			return nil, ErrGap
		}
	}
	return release, nil
}

func captureNative(ctx context.Context, cfg HookConfig, r *Recorder, artifacts []Package) (Snapshot, error) {
	previous, e := r.endpoint(ctx, cfg.Baseline)
	if e != nil {
		return Snapshot{}, e
	}
	old, e := packageMap(previous.Packages)
	if e != nil {
		return Snapshot{}, e
	}
	raw, e := readRootFile("/var/lib/dpkg/status", cfg.Profile.Limits.Bytes)
	if e != nil {
		return Snapshot{}, e
	}
	paragraphs, e := parseParagraphs(raw)
	if e != nil || len(paragraphs) > cfg.Profile.Limits.Members {
		return Snapshot{}, ErrGap
	}
	snapshot := Snapshot{Packages: []Package{}, Leaves: []Leaf{}}
	owners := map[string][]string{}
	packageByKey := map[string]Package{}
	for _, row := range paragraphs {
		if ctx.Err() != nil {
			return Snapshot{}, ErrGap
		}
		name, arch, version := row["Package"], row["Architecture"], row["Version"]
		state := row["Status"]
		if state == "deinstall ok config-files" || state == "purge ok not-installed" {
			continue
		}
		if name == "" || arch == "" || version == "" {
			return Snapshot{}, ErrGap
		}
		pkg := Package{Name: name, Version: version, Architecture: arch, Status: "incomplete"}
		if state == "install ok installed" {
			pkg.Status = "installed"
		} else {
			if fields := strings.Fields(state); len(fields) == 3 && fields[0] == "install" && fields[1] == "ok" {
				pkg.Status = fields[2]
			}
			snapshot.PendingTriggers = true
		}
		if prior, ok := old[pkg.key()]; ok && prior.Version == pkg.Version {
			pkg.ArchiveSHA256 = prior.ArchiveSHA256
		}
		for _, a := range artifacts {
			if a.key() == pkg.key() && a.Version == pkg.Version {
				pkg.ArchiveSHA256 = a.ArchiveSHA256
			}
		}
		snapshot.Packages = append(snapshot.Packages, pkg)
		packageByKey[pkg.key()] = pkg
		// The profile supports exact ordinary dpkg payload ownership only. Diversions,
		// alternatives, usr-merge remapping and unknown/multiple owners refuse below.
		list, e := readRootFile("/var/lib/dpkg/info/"+pkg.key()+".list", cfg.Profile.Limits.Bytes)
		if e != nil {
			list, e = readRootFile("/var/lib/dpkg/info/"+pkg.Name+".list", cfg.Profile.Limits.Bytes)
		}
		if e != nil {
			return Snapshot{}, ErrOwnership
		}
		for _, line := range strings.Split(string(list), "\n") {
			for _, m := range cfg.Profile.Mappings {
				if line == m.Path {
					owners[m.Path] = append(owners[m.Path], pkg.key())
				}
			}
		}
	}
	diversions, e := readRootFile("/var/lib/dpkg/diversions", cfg.Profile.Limits.Bytes)
	if e != nil {
		return Snapshot{}, ErrOwnership
	}
	diversionLines := strings.Split(strings.TrimSuffix(string(diversions), "\n"), "\n")
	if len(diversions) > 0 && len(diversionLines)%3 != 0 {
		return Snapshot{}, ErrOwnership
	}
	for n, line := range diversionLines {
		if n%3 == 2 {
			continue
		}
		for _, m := range cfg.Profile.Mappings {
			if line == m.Path {
				return Snapshot{}, ErrOwnership
			}
		}
	}
	for _, m := range cfg.Profile.Mappings {
		if len(owners[m.Path]) != 1 || owners[m.Path][0] != m.Package+":"+m.Architecture {
			return Snapshot{}, ErrOwnership
		}
		if _, ok := packageByKey[owners[m.Path][0]]; !ok {
			return Snapshot{}, ErrOwnership
		}
		bytes, e := readRootFile(m.Path, cfg.Profile.Limits.Bytes)
		if e != nil {
			return Snapshot{}, e
		}
		// Bind the same protected descriptor's metadata/content through a second
		// pinned read, under package exclusion; no symlink/alias adoption is allowed.
		f, e := pinnedFile(FilePin{m.Path, Digest(bytes)}, 0, "/", cfg.Profile.Limits.Bytes)
		if e != nil {
			return Snapshot{}, e
		}
		var st unix.Stat_t
		e = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if e != nil || st.Nlink != 1 {
			return Snapshot{}, ErrOwnership
		}

		md5Bytes, e := packageMetadata(m.Package+":"+m.Architecture, m.Package, "md5sums", cfg.Profile.Limits.Bytes, false)
		if e != nil {
			return Snapshot{}, e
		}
		md5sum, e := checksumEntry(md5Bytes, strings.TrimPrefix(m.Path, "/"), 32)
		if e != nil {
			return Snapshot{}, e
		}
		shaBytes, e := packageMetadata(m.Package+":"+m.Architecture, m.Package, "sha256sums", cfg.Profile.Limits.Bytes, true)
		if e != nil {
			return Snapshot{}, e
		}
		shaSum := ""
		if len(shaBytes) > 0 {
			shaSum, e = checksumEntry(shaBytes, strings.TrimPrefix(m.Path, "/"), 64)
			if e != nil {
				return Snapshot{}, e
			}
		}
		if e = retainArtifact(bytes, cfg.Profile.Limits); e != nil {
			return Snapshot{}, e
		}
		snapshot.Leaves = append(snapshot.Leaves, Leaf{MD5: md5sum, DpkgSHA256: shaSum, Path: m.Path, Package: m.Package, Architecture: m.Architecture, SHA256: Digest(bytes), Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid})
	}
	sort.Slice(snapshot.Packages, func(i, j int) bool { return snapshot.Packages[i].key() < snapshot.Packages[j].key() })
	sort.Slice(snapshot.Leaves, func(i, j int) bool { return snapshot.Leaves[i].Path < snapshot.Leaves[j].Path })
	if !snapshot.valid(cfg.Profile.Limits) {
		return Snapshot{}, ErrGap
	}
	return snapshot, nil
}
func captureArchives(ctx context.Context, p Profile, args []string) ([]Package, error) {
	out := []Package{}
	seen := map[string]bool{}
	requiresArchive := false
	for _, arg := range args {
		if arg == "--unpack" || arg == "--install" || arg == "-i" {
			requiresArchive = true
		}
		if !strings.HasSuffix(arg, ".deb") {
			continue
		}
		if !leafPath(arg) {
			return nil, ErrGap
		}
		fd, e := unix.Open(arg, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return nil, ErrMissing
		}
		f := os.NewFile(uintptr(fd), arg)
		var st unix.Stat_t
		e = unix.Fstat(fd, &st)
		if e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > p.Limits.Bytes {
			f.Close()
			return nil, ErrMissing
		}
		b, e := io.ReadAll(io.LimitReader(f, p.Limits.Bytes+1))
		f.Close()
		if e != nil || int64(len(b)) > p.Limits.Bytes {
			return nil, ErrMissing
		}
		payload, e := readDeb(ctx, p, b)
		if e != nil {
			return nil, e
		}
		pkg := Package{Name: payload.control["Package"], Version: payload.control["Version"], Architecture: payload.control["Architecture"], Status: "archive", ArchiveSHA256: Digest(b)}
		if !nameRE.MatchString(pkg.Name) || !nameRE.MatchString(pkg.Architecture) || !validVersion(pkg.Version) || seen[pkg.key()] {
			return nil, ErrGap
		}
		seen[pkg.key()] = true
		if e = retainArtifact(b, p.Limits); e != nil {
			return nil, e
		}
		out = append(out, pkg)
	}
	if requiresArchive && len(out) == 0 {
		return nil, ErrMissing
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}
func retainArtifact(b []byte, l Limits) error {
	d, e := openProtectedDir("/opt/swarma/lib/user-manager/update-artifacts", 0, "/")
	if e != nil {
		return e
	}
	defer d.Close()
	// The global package-writer exclusion serializes native hook producers. There
	// is no acquisition component or arbitrary concurrent evidence writer here.
	fd, e := unix.Openat(int(d.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return ErrStore
	}
	listing := os.NewFile(uintptr(fd), "objects")
	names, e := listing.Readdirnames(l.Entries + 1)
	listing.Close()
	if e != nil && e != io.EOF || len(names) > l.Entries {
		return ErrStore
	}
	name := Digest(b)
	var total int64
	for _, n := range names {
		if !digestOK(n) {
			return ErrStore
		}
		fd, e := unix.Openat(int(d.Fd()), n, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if e != nil {
			return ErrStore
		}
		f := os.NewFile(uintptr(fd), n)
		if protected(f, 0, false) != nil {
			f.Close()
			return ErrStore
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return ErrStore
		}
		total += st.Size()
		if n == name {
			old, e := io.ReadAll(io.LimitReader(f, l.Bytes+1))
			f.Close()
			if e != nil || Digest(old) != name {
				return ErrStore
			}
			return nil
		}
		f.Close()
	}
	if len(names) >= l.Entries || total+int64(len(b)) > l.Bytes {
		return ErrStore
	}
	fd, e = unix.Openat(int(d.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrStore
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if protected(f, 0, false) != nil {
		return ErrStore
	}
	if n, e := f.Write(b); e != nil || n != len(b) {
		return ErrStore
	}
	if f.Sync() != nil || f.Close() != nil || d.Sync() != nil {
		return ErrStore
	}
	return nil
}

func supportedNativeProfile(p Profile) bool {
	return p.FutureSkewConfirmed && p.FutureSkew == UbuntuReleaseFutureSkew && p.MaxAge == UbuntuReleaseMaxAge && p.P7Deadline == RevocationResponseDeadline && p.Distribution == "ubuntu" && p.Release == "26.04" && p.Architecture == "amd64" && p.Origin == "Ubuntu" && p.Component == "main" && nameRE.MatchString(p.Codename) && (p.Suite == p.Codename || p.Suite == p.Codename+"-updates" || p.Suite == p.Codename+"-security")
}

func packageMetadata(qualified, name, suffix string, limit int64, optional bool) ([]byte, error) {
	d, e := openProtectedDir("/var/lib/dpkg/info", 0, "/")
	if e != nil {
		return nil, ErrChecksum
	}
	defer d.Close()
	for _, n := range []string{qualified + "." + suffix, name + "." + suffix} {
		var st unix.Stat_t
		e := unix.Fstatat(int(d.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW)
		if e == unix.ENOENT {
			continue
		}
		if e != nil {
			return nil, ErrChecksum
		}
		b, e := readRootFile("/var/lib/dpkg/info/"+n, limit)
		if e != nil {
			return nil, ErrChecksum
		}
		return b, nil
	}
	if optional {
		return nil, nil
	}
	return nil, ErrChecksum
}
func checksumEntry(b []byte, path string, length int) (string, error) {
	found := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != length {
			return "", ErrChecksum
		}
		for _, c := range fields[0] {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return "", ErrChecksum
			}
		}
		if fields[1] == path {
			if found != "" {
				return "", ErrChecksum
			}
			found = fields[0]
		}
	}
	if found == "" {
		return "", ErrChecksum
	}
	return found, nil
}
