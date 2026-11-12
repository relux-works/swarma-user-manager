//go:build linux

package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func fixtureFenceBinary(t *testing.T) {
	t.Helper()
	requireHostedRoot(t)
	if _, err := os.Lstat(fenceBinaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fixture fence path must initially be absent")
	}
	if err := os.MkdirAll(filepath.Dir(fenceBinaryPath), 0755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	b, err := readBounded(source, 64*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(fenceBinaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(fenceBinaryPath); err != nil {
			t.Error(err)
		}
	})
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0755)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		t.Fatal(err)
	}
}

type fencePlant struct {
	Kind   string `json:"kind"`
	GHA    string `json:"gha"`
	Runner string `json:"runner"`
	Opt    string `json:"opt"`
}

// This fault hook exists only in the fixture's copied test binary, not the
// production command. A protected plan is created only after the actual hosted
// root gate passes. It mutates solely the current positively owned test unit.
func testFenceEntry(args []string) int {
	if len(args) != 2 || os.Geteuid() != 0 || !slotPattern.MatchString(args[0]) {
		return EnforcementFence(args)
	}
	root, err := openTrustedDir(fenceRootPath)
	if err != nil {
		return EnforcementFence(args)
	}
	f, err := childFD(root, "plant-"+args[0]+".json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		root.Close()
		return EnforcementFence(args)
	}
	if err != nil {
		root.Close()
		return 98
	}
	b, err := readProtectedFD(f, 0600, 1024)
	f.Close()
	var plan fencePlant
	if err != nil || json.Unmarshal(b, &plan) != nil || !rootTestAllowed(os.Geteuid(), plan.GHA, plan.Runner, plan.Opt) {
		root.Close()
		return 98
	}
	q, err := readFenceRequest(root, args[0], args[1])
	root.Close()
	if err != nil {
		return 98
	}
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(self) != "0::"+q.Record.Cgroup+"\n" {
		return 98
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = plantFenceFault(plan.Kind, q); err != nil {
		return 98
	}
	return EnforcementFence(args)
}
func plantFenceFault(kind string, q fenceRequest) error {
	path := "/sys/fs/cgroup" + q.Record.Cgroup
	switch kind {
	case "station_bootstrap":
		// Baseline admission must succeed before the bounded known violation.
		// The caller already verified this is its positively owned test cgroup.
		// Like the fence itself, resolve custody below PID 1's root.
		roots, err := openHostStationRoots()
		if err != nil {
			return err
		}
		defer roots.close()
		if err = verifyStationInputs(roots, q.Policy, &q.Record); err != nil {
			return err
		}
		view, err := openStationView(roots, &q.Record)
		if err != nil {
			return err
		}
		defer view.close()
		parent, err := stationParent(roots, q.Record.Identity.UID, stationSpecFor("bootstrap"))
		if err != nil {
			return err
		}
		defer parent.Close()
		f, err := childFD(parent, "bootstrap", unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		identity, ok := q.Record.Station.object("bootstrap")
		if !ok {
			return errStationCustody
		}
		if err = checkStationObject(f, stationSpecFor("bootstrap"), q.Record.Identity.UID, identity); err != nil {
			return err
		}
		if err = f.Truncate(0); err != nil {
			return err
		}
		return f.Sync()
	case "wrong_limit":
		return os.WriteFile(filepath.Join(path, "memory.max"), []byte(strconv.FormatUint(memoryBytes(q.Policy.Caps.MemoryMax)+4096, 10)), 0600)
	case "missing_nft":
		if err := verifyNFT(context.Background(), q.Policy, &q.Record); err != nil {
			return err
		}
		_, err := runFixedTool(context.Background(), toolInvocation{Path: nftPath, Args: []string{"delete", "table", "inet", q.Record.Identity.Table}})
		return err
	case "wrong_bpf_program":
		c, err := os.Open(path)
		if err != nil {
			return err
		}
		defer c.Close()
		id, err := cgroupProgram(int(c.Fd()), unix.BPF_CGROUP_INET_EGRESS)
		if err != nil {
			return err
		}
		old, err := bpfFD(unix.BPF_PROG_GET_FD_BY_ID, id)
		if err != nil {
			return err
		}
		defer unix.Close(old)
		program, err := inspectProgram(old)
		if err != nil {
			return err
		}
		map4, map6 := -1, -1
		for _, id := range program.maps {
			fd, err := bpfFD(unix.BPF_MAP_GET_FD_BY_ID, id)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			bits, err := verifyAllowMap(fd, q.Policy)
			if err != nil {
				return err
			}
			if bits == 32 {
				map4 = fd
			} else {
				map6 = fd
			}
		}
		instructions := firewallInstructions(map4, map6, false)
		// Keep the exact policy maps, but remove deny-any's verdict bit. This
		// makes non-allowlisted traffic pass and must fail bytecode comparison.
		instructions[len(instructions)-5].Imm = 0
		bad, err := loadReference(instructions)
		if err != nil {
			return err
		}
		defer unix.Close(bad)
		a := make([]byte, 16)
		put32(a, 0, uint32(c.Fd()))
		put32(a, 4, uint32(old))
		put32(a, 8, unix.BPF_CGROUP_INET_EGRESS)
		if _, err = bpfCall(unix.BPF_PROG_DETACH, a); err != nil {
			return err
		}
		put32(a, 4, uint32(bad))
		put32(a, 12, unix.BPF_F_ALLOW_MULTI)
		_, err = bpfCall(unix.BPF_PROG_ATTACH, a)
		return err
	case "missing_bpf":
		c, err := os.Open(path)
		if err != nil {
			return err
		}
		defer c.Close()
		for _, hook := range []uint32{unix.BPF_CGROUP_INET_INGRESS, unix.BPF_CGROUP_INET_EGRESS} {
			id, err := cgroupProgram(int(c.Fd()), hook)
			if err != nil {
				return err
			}
			fd, err := bpfFD(unix.BPF_PROG_GET_FD_BY_ID, id)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			a := make([]byte, 16)
			put32(a, 0, uint32(c.Fd()))
			put32(a, 4, uint32(fd))
			put32(a, 8, hook)
			if _, err = bpfCall(unix.BPF_PROG_DETACH, a); err != nil {
				return err
			}
		}
		return nil
	case "wrong_bpf_map":
		c, err := os.Open(path)
		if err != nil {
			return err
		}
		defer c.Close()
		id, err := cgroupProgram(int(c.Fd()), unix.BPF_CGROUP_INET_EGRESS)
		if err != nil {
			return err
		}
		fd, err := bpfFD(unix.BPF_PROG_GET_FD_BY_ID, id)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		program, err := inspectProgram(fd)
		if err != nil || len(program.maps) == 0 {
			return errFenceBPFPolicy
		}
		m, err := bpfFD(unix.BPF_MAP_GET_FD_BY_ID, program.maps[0])
		if err != nil {
			return err
		}
		defer unix.Close(m)
		info := make([]byte, 88)
		if err = bpfInfo(m, info); err != nil {
			return err
		}
		key := make([]byte, get32(info, 8))
		if err = bpfMapElement(unix.BPF_MAP_GET_NEXT_KEY, m, nil, key); err != nil {
			return err
		}
		if err = bpfMapElement(unix.BPF_MAP_DELETE_ELEM, m, key, nil); err != nil {
			return err
		}
		// Replace a real permitted prefix with /0: the same attached bytecode
		// would now allow every address in this family if the fence missed it.
		value := make([]byte, 8)
		put64(value, 0, 1)
		return bpfMapElement(unix.BPF_MAP_UPDATE_ELEM, m, make([]byte, len(key)), value)
	case "unsupported", "unknown":
		code := uint32(unix.EOPNOTSUPP)
		if kind == "unknown" {
			code = uint32(unix.EIO)
		}
		filter := []unix.SockFilter{{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(unix.SYS_BPF)}, {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | code}, {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}}
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		var pin runtime.Pinner
		pin.Pin(&filter[0])
		pin.Pin(&prog)
		defer pin.Unpin()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
		err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0)
		runtime.KeepAlive(filter)
		runtime.KeepAlive(prog)
		return err
	}
	return errFenceInput
}

// Proves the real ExecStartPre gate precedes payload execution: actual kernel BPF removal/map widening, wrong limit, missing NFT and syscall failures all retain the payload sentinel's absence beside a valid launch.
func TestRootEnforcementFence(t *testing.T) {
	requireHostedRoot(t)
	t.Run("info_query_buffers", func(t *testing.T) {
		// Proves the old returned-info reuse requests unbuffered JIT output and
		// fails specifically with EFAULT; the bounded fresh request must succeed
		// for that same real, unattached kernel program. No payload is executed.
		fd, err := loadReference(firewallInstructions(-1, -1, false))
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		info := make([]byte, 128)
		if err = bpfInfo(fd, info); err != nil {
			t.Fatal(err)
		}
		n := get32(info, 20)
		if n == 0 || n > 8192 || get32(info, 52) != 0 || get32(info, 104) == 0 {
			t.Fatal("kernel did not supply the regression witness metadata")
		}
		code := make([]byte, n)
		defer pinBytes(code)()
		put64(info, 32, ptr64(code))
		if err = bpfInfo(fd, info); !errors.Is(err, unix.EFAULT) {
			t.Fatalf("unbuffered returned-info reuse: %v, want EFAULT", err)
		}
		program, err := inspectProgram(fd)
		if err != nil || len(program.code) != int(n) || len(program.maps) != 0 {
			t.Fatalf("bounded code-only query: %v", err)
		}
	})
	for _, tc := range []struct {
		kind string
		want error
	}{{"valid", nil}, {"missing_bpf", errFenceBPFMissing}, {"wrong_limit", errFenceLimits}, {"missing_nft", errFenceNFT}, {"wrong_bpf_map", errFenceBPFPolicy}, {"wrong_bpf_program", errFenceBPFPolicy}, {"unsupported", errFenceBPFUnsupported}, {"unknown", errFenceBPFUnknown}} {
		t.Run(tc.kind, func(t *testing.T) {
			p, r, dir := rootFixture(t)
			sentinel := filepath.Join(r.Identity.Home, "executed")
			setProbePolicy(t, &p, dir, probeSpec{Report: sentinel, Hold: true})
			engine, store, _ := realEngine(t, p, &r, dir)
			var cause error
			engine.diagnostic = func(_ string, err error) { cause = err; t.Log(err) }
			created, code := engine.apply(context.Background(), currentCreate(t, &r))
			if code != "" {
				if created != nil {
					r = *created
				}
				t.Fatal(code)
			}
			r = *created
			if tc.kind != "valid" {
				root, err := openFenceRoot()
				if err != nil {
					t.Fatal(err)
				}
				plan := fencePlant{tc.kind, os.Getenv("GITHUB_ACTIONS"), os.Getenv("RUNNER_ENVIRONMENT"), os.Getenv("SLOTD_ROOT_TESTS")}
				b, err := json.Marshal(plan)
				if err == nil {
					err = atomicPrivate(root, "plant-"+r.Slot+".json", append(b, '\n'))
				}
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.Remove(filepath.Join(fenceRootPath, "plant-"+r.Slot+".json")); err != nil {
						t.Error(err)
					}
				})
			}
			started, code := engine.apply(context.Background(), request{Op: "start", Slot: r.Slot})
			if started != nil {
				r = *started
			}
			if tc.want == nil {
				if code != "" || r.Binding.State != running {
					t.Fatalf("positive launch: %s, %v", code, cause)
				}
				awaitProbe(t, sentinel, 0)
			} else {
				if code != internalError || !errors.Is(cause, tc.want) || r.Binding.State != failed {
					t.Fatalf("wrong activation refusal: %s, %v", code, cause)
				}
				if _, err := os.Lstat(sentinel); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed fence executed payload")
				}
				stored, err := store.load(r.Slot)
				if err != nil || stored == nil || stored.Binding.State != failed {
					t.Fatal("failed fence was not durable")
				}
				observed, err := observeAccounts(context.Background(), r.Identity)
				if err != nil || observed.matches(r.Accounts) != nil {
					t.Fatal("fence failure changed accounts")
				}
				if _, err = os.Stat(filepath.Join(r.Identity.Home, "bootstrap")); err != nil {
					t.Fatal("fence failure changed home")
				}
				if tc.kind != "missing_nft" {
					if err = verifyNFT(context.Background(), p, &r); err != nil {
						t.Fatal("fence failure changed NFT")
					}
				}
			}
		})
	}
}
