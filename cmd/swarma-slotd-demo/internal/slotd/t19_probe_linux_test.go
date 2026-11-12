//go:build linux

package slotd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The T19 probe is the payload of a real slot. It runs as the slot UID and
// reports one verdict per target: "ok" for a completed connect (or echo), or
// the exact errno name. It never decides pass/fail; the root test does.
type t19Target struct {
	Network, Address string
	Echo             bool
}

type t19Spec struct {
	Report        string
	Phase1        string
	Inventory     bool
	Pathnames     []string
	Abstract      []string
	Wallet        string
	Frame         string
	WalletRestart bool
	JournalLine   string
	Families      bool
	Tamper        bool
	IP            []t19Target
	Hold          bool
	// KeyFile: read it, then try to open it for writing and to chmod it.
	KeyFile string
}

type t19Report struct {
	UID           int
	GID           int
	Groups        []int
	KeyRead       string
	KeyWrite      string
	KeyChmod      string
	Sockets       []string
	WalkErrors    []t19WalkError
	Pathnames     map[string]string
	Abstract      map[string]string
	Wallet        string
	WalletErr     string
	WalletRestart string
	Families      map[string]string
	Tamper        map[string]string
	AfterTamper   map[string]string
	IP            map[string]string
}

func errnoName(err error) string {
	if err == nil {
		return "ok"
	}
	var errno unix.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
		return errno.Error()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return "error:" + err.Error()
}

// unixVerdict connects with each socket type in turn: EPROTOTYPE proves the
// name resolved to a socket of another type, so it is retried, never counted
// as a refusal. Abstract names are passed with a leading "@".
func unixVerdict(name string) string {
	for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET} {
		fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return errnoName(err)
		}
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: name})
		unix.Close(fd)
		if errors.Is(err, unix.EPROTOTYPE) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return "ok"
		}
		return errnoName(err)
	}
	return "EPROTOTYPE"
}

var dnsRootQuery = []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01}

func ipVerdict(target t19Target) string {
	if strings.HasPrefix(target.Network, "udp") {
		c, err := net.Dial(target.Network, target.Address)
		if err != nil {
			return errnoName(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
		if _, err = c.Write(dnsRootQuery); err != nil {
			return errnoName(err)
		}
		var b [512]byte
		_, err = c.Read(b[:])
		return errnoName(err)
	}
	c, err := net.DialTimeout(target.Network, target.Address, 1500*time.Millisecond)
	if err != nil {
		return errnoName(err)
	}
	defer c.Close()
	if !target.Echo {
		return "ok"
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte("probe")); err != nil {
		return errnoName(err)
	}
	var b [5]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		return errnoName(err)
	}
	if string(b[:]) != "probe" {
		return "echo-mismatch"
	}
	return "ok"
}

func walletExchange(path, frame string) (string, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte(frame)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(c, 4096))
	return string(b), err
}

// tamper runs on one locked thread that is discarded afterwards: a second
// Landlock layer binds only this thread, and the follow-up connects must run
// on the same thread to observe it.
func t19Tamper(spec t19Spec, report *t19Report) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		tamper := map[string]string{}
		// unshare in a single-threaded forked child: Go's own threads would
		// make CLONE_NEWUSER fail with EINVAL regardless of the slot layers.
		cmd := exec.Command("/usr/bin/true")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET}
		tamper["unshare-user-net"] = errnoName(cmd.Run())
		empty := unix.LandlockRulesetAttr{}
		_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&empty)), unsafe.Sizeof(empty), 0)
		tamper["landlock-empty-scope"] = errnoName(errnoOrNil(errno))
		layer := unix.LandlockRulesetAttr{Access_fs: unix.LANDLOCK_ACCESS_FS_MAKE_SOCK}
		fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&layer)), unsafe.Sizeof(layer), 0)
		if errno == 0 {
			_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0)
			unix.Close(int(fd))
		}
		tamper["landlock-unscoped-layer"] = errnoName(errnoOrNil(errno))
		tamper["prctl-no-new-privs-0"] = errnoName(unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0))
		tamper["prctl-ambient-net-admin"] = errnoName(unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_ADMIN, 0, 0))
		tamper["prctl-dumpable-1"] = errnoName(unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0))
		after := map[string]string{}
		for _, name := range spec.Abstract {
			after["@"+name] = unixVerdict("@" + name)
		}
		for _, path := range spec.Pathnames {
			after[path] = unixVerdict(path)
		}
		report.Tamper, report.AfterTamper = tamper, after
	}()
	<-done
}

func errnoOrNil(errno unix.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

func writeT19Report(path string, report t19Report) error {
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	tmp := path + ".partial"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func runT19Probe(args []string) int {
	if len(args) != 1 || os.Geteuid() == 0 {
		return 91
	}
	var spec t19Spec
	if json.Unmarshal([]byte(args[0]), &spec) != nil || !filepath.IsAbs(spec.Report) {
		return 92
	}
	if spec.JournalLine != "" {
		fmt.Println(spec.JournalLine)
	}
	report := t19Report{UID: os.Getuid(), Pathnames: map[string]string{}, Abstract: map[string]string{}, IP: map[string]string{}}
	report.GID = os.Getgid()
	report.Groups, _ = os.Getgroups()
	if spec.KeyFile != "" {
		_, err := os.ReadFile(spec.KeyFile)
		report.KeyRead = errnoName(err)
		f, err := os.OpenFile(spec.KeyFile, os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			f.Close()
		}
		report.KeyWrite = errnoName(err)
		report.KeyChmod = errnoName(unix.Chmod(spec.KeyFile, 0666))
	}
	if spec.Inventory {
		// Every failure keeps its path, errno and whether this UID can still
		// resolve names below it. /proc is procfs (socketless); root's view
		// walk checks that by mount facts, so it is recorded like a failure.
		var st unix.Stat_t
		report.WalkErrors = append(report.WalkErrors, t19WalkError{Path: "/proc", Errno: "pruned", Search: errnoName(unix.Stat("/proc/.", &st))})
		_ = filepath.WalkDir("/", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				report.WalkErrors = append(report.WalkErrors, t19WalkError{Path: p, Errno: errnoName(err), Search: errnoName(unix.Stat(p+"/.", &st))})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if p == "/proc" {
				return fs.SkipDir
			}
			if d.Type()&fs.ModeSocket != 0 {
				report.Sockets = append(report.Sockets, p)
			}
			return nil
		})
	}
	for _, path := range spec.Pathnames {
		report.Pathnames[path] = unixVerdict(path)
	}
	for _, name := range spec.Abstract {
		report.Abstract["@"+name] = unixVerdict("@" + name)
	}
	if spec.Wallet != "" {
		reply, err := walletExchange(spec.Wallet, spec.Frame)
		report.Wallet, report.WalletErr = reply, errnoName(err)
	}
	if spec.Families {
		report.Families = map[string]string{}
		for name, f := range map[string][3]int{"netlink": {unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE}, "packet": {unix.AF_PACKET, unix.SOCK_RAW, 0}, "unix": {unix.AF_UNIX, unix.SOCK_STREAM, 0}, "inet": {unix.AF_INET, unix.SOCK_STREAM, 0}, "inet6": {unix.AF_INET6, unix.SOCK_STREAM, 0}} {
			fd, err := unix.Socket(f[0], f[1]|unix.SOCK_CLOEXEC, f[2])
			if err == nil {
				unix.Close(fd)
			}
			report.Families[name] = errnoName(err)
		}
	}
	for _, target := range spec.IP {
		report.IP[target.Network+" "+target.Address] = ipVerdict(target)
	}
	if spec.Tamper {
		t19Tamper(spec, &report)
	}
	if spec.Phase1 != "" {
		if writeT19Report(spec.Phase1, report) != nil {
			return 93
		}
	}
	if spec.WalletRestart {
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			reply, err := walletExchange(spec.Wallet, spec.Frame)
			if err == nil && strings.Contains(reply, `"generation":2`) {
				report.WalletRestart = reply
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if writeT19Report(spec.Report, report) != nil {
		return 94
	}
	if spec.Hold {
		for {
			time.Sleep(time.Hour)
		}
	}
	return 0
}

// runT19FakeABIPayload must never run: it is the payload behind a launcher
// whose Landlock probe is faked below ABI 6. If exec'd, it leaves a marker.
func runT19FakeABIPayload(args []string) int {
	if len(args) == 1 && filepath.IsAbs(args[0]) {
		_ = os.WriteFile(args[0], []byte("payload ran"), 0600)
	}
	for {
		time.Sleep(time.Hour)
	}
}

// testSlotLaunch is the test binary's launcher entry. It is the production
// slotLaunch; only the T19.10 fixture argv swaps the ABI probe for a fake.
func testSlotLaunch(args []string) int {
	abi := landlockABI
	if len(args) > 1 && args[1] == "slotd-t19-fake-abi" {
		abi = func() (int, error) { return 5, nil }
	}
	return slotLaunch(args, abi, unix.Exec)
}
