//go:build linux

package slotd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These bounded layouts are the Linux BPF UAPI, not systemd's configuration
// objects. All queried FDs remain open until verification completes.
func bpfCall(command int, attr []byte) (int, error) {
	defer pinBytes(attr)()
	r, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	runtime.KeepAlive(attr)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// UAPI attrs hold integer addresses, which the GC cannot discover. Pin buffers
// before conversion so stack growth and collection cannot invalidate them.
func pinBytes(buffers ...[]byte) func() {
	var pin runtime.Pinner
	for _, b := range buffers {
		if len(b) > 0 {
			pin.Pin(&b[0])
		}
	}
	return pin.Unpin
}
func put32(b []byte, offset int, value uint32) { binary.NativeEndian.PutUint32(b[offset:], value) }
func put64(b []byte, offset int, value uint64) { binary.NativeEndian.PutUint64(b[offset:], value) }
func get32(b []byte, offset int) uint32        { return binary.NativeEndian.Uint32(b[offset:]) }
func ptr64(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}
func bpfInfo(fd int, info []byte) error {
	defer pinBytes(info)()
	a := make([]byte, 16)
	put32(a, 0, uint32(fd))
	put32(a, 4, uint32(len(info)))
	put64(a, 8, ptr64(info))
	_, err := bpfCall(unix.BPF_OBJ_GET_INFO_BY_FD, a)
	runtime.KeepAlive(info)
	return err
}
func bpfFD(command int, id uint32) (int, error) {
	a := make([]byte, 12)
	put32(a, 0, id)
	return bpfCall(command, a)
}
func cgroupProgram(cgroupFD int, attach uint32) (uint32, error) {
	ids := make([]byte, 8)
	defer pinBytes(ids)()
	a := make([]byte, 32)
	put32(a, 0, uint32(cgroupFD))
	put32(a, 4, attach)
	put64(a, 16, ptr64(ids))
	put32(a, 24, 2)
	_, err := bpfCall(unix.BPF_PROG_QUERY, a)
	runtime.KeepAlive(ids)
	if err != nil {
		return 0, err
	}
	if get32(a, 24) == 0 {
		return 0, errFenceBPFMissing
	}
	if get32(a, 24) != 1 || get32(ids, 0) == 0 {
		return 0, errFenceBPFPolicy
	}
	return get32(ids, 0), nil
}

type kernelProgram struct {
	code []byte
	maps []uint32
}

func inspectProgram(fd int) (kernelProgram, error) {
	var p kernelProgram
	i := make([]byte, 128)
	if err := bpfInfo(fd, i); err != nil {
		return p, err
	}
	n, m := get32(i, 20), get32(i, 52)
	if get32(i, 0) != unix.BPF_PROG_TYPE_CGROUP_SKB || n == 0 || n > 8192 || n%8 != 0 || m > 2 {
		return p, errFenceBPFPolicy
	}
	p.code = make([]byte, n)
	ids := make([]byte, m*4)
	defer pinBytes(p.code, ids)()
	// Returned lengths/counts are also next-call inputs. Reusing the complete
	// first response requests JIT bytes/symbols without their buffers (EFAULT).
	// Request only the bounded translated code and map IDs that we inspect.
	i = make([]byte, 128)
	put32(i, 20, n)
	put32(i, 52, m)
	put64(i, 32, ptr64(p.code))
	put64(i, 56, ptr64(ids))
	if err := bpfInfo(fd, i); err != nil {
		return kernelProgram{}, err
	}
	runtime.KeepAlive(p.code)
	runtime.KeepAlive(ids)
	if get32(i, 20) != n || get32(i, 52) != m {
		return kernelProgram{}, errFenceBPFPolicy
	}
	if bytes.Equal(p.code, make([]byte, len(p.code))) {
		return kernelProgram{}, errFenceBPFPolicy
	}
	for k := uint32(0); k < m; k++ {
		p.maps = append(p.maps, get32(ids, int(k*4)))
	}
	return p, nil
}
func bpfMapElement(command, fd int, key, value []byte) error {
	defer pinBytes(key, value)()
	a := make([]byte, 32)
	put32(a, 0, uint32(fd))
	put64(a, 8, ptr64(key))
	put64(a, 16, ptr64(value))
	_, err := bpfCall(command, a)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// Expanding at most 256 addresses compares the exact union even when systemd
// coalesces adjacent host entries into an LPM prefix. Extra prefixes are refused.
func verifyAllowMap(fd int, p policy) (int, error) {
	i := make([]byte, 88)
	if err := bpfInfo(fd, i); err != nil {
		return 0, err
	}
	keySize := get32(i, 8)
	if get32(i, 0) != unix.BPF_MAP_TYPE_LPM_TRIE || (keySize != 8 && keySize != 20) || get32(i, 12) != 8 || get32(i, 16) == 0 || get32(i, 16) > 256 || get32(i, 20) != unix.BPF_F_NO_PREALLOC {
		return 0, errFenceBPFPolicy
	}
	bits := 32
	if keySize == 20 {
		bits = 128
	}
	want := map[netip.Addr]bool{}
	for _, rule := range p.Egress {
		a, err := netip.ParseAddr(rule.Addr)
		if err != nil {
			return 0, errFenceBPFPolicy
		}
		if a.BitLen() == bits {
			want[a] = true
		}
	}
	if len(want) == 0 {
		return 0, errFenceBPFPolicy
	}
	seen := map[netip.Addr]bool{}
	var previous []byte
	for count := 0; ; count++ {
		next := make([]byte, keySize)
		err := bpfMapElement(unix.BPF_MAP_GET_NEXT_KEY, fd, previous, next)
		if errors.Is(err, unix.ENOENT) {
			break
		}
		if err != nil {
			return 0, err
		}
		if count >= 256 {
			return 0, errFenceBPFPolicy
		}
		prefix := get32(next, 0)
		if prefix > uint32(bits) || uint32(bits)-prefix > 8 {
			return 0, errFenceBPFPolicy
		}
		a, ok := netip.AddrFromSlice(next[4:])
		if !ok {
			return 0, errFenceBPFPolicy
		}
		if netip.PrefixFrom(a, int(prefix)).Masked().Addr() != a {
			return 0, errFenceBPFPolicy
		}
		value := make([]byte, 8)
		if err = bpfMapElement(unix.BPF_MAP_LOOKUP_ELEM, fd, next, value); err != nil {
			return 0, err
		}
		if binary.NativeEndian.Uint64(value) != 1 {
			return 0, errFenceBPFPolicy
		}
		for n := 0; n < 1<<uint(uint32(bits)-prefix); n++ {
			if !want[a] || seen[a] {
				return 0, errFenceBPFPolicy
			}
			seen[a] = true
			a = a.Next()
		}
		previous = next
	}
	if len(seen) != len(want) {
		return 0, errFenceBPFPolicy
	}
	return bits, nil
}

type bpfInstruction struct {
	Code, Regs uint8
	Off        int16
	Imm        int32
}

func ins(code, dst, src uint8, off int16, imm int32) bpfInstruction {
	return bpfInstruction{code, dst | src<<4, off, imm}
}

// The closed systemd firewall form: no accounting, deny-any, exact IPv4/IPv6
// allow maps. Unknown compiler forms refuse activation. Reference instructions
// are verified and translated by this kernel but NEVER attached or executed.
func firewallInstructions(map4, map6 int, ingress bool) []bpfInstruction {
	b := []bpfInstruction{ins(0xbf, 6, 1, 0, 0), ins(0x61, 7, 6, 16, 0), ins(0xb4, 8, 0, 0, 0)}
	for _, family := range []struct{ fd, size, protocol, offset int }{{map4, 4, 0x0008, 16}, {map6, 16, 0xdd86, 24}} {
		if family.fd < 0 {
			continue
		}
		offset := family.offset
		if ingress {
			offset -= family.size
		}
		b = append(b, ins(0x55, 7, 0, 14, int32(family.protocol)), ins(0xbf, 1, 6, 0, 0), ins(0xb4, 2, 0, 0, int32(offset)),
			ins(0xbf, 3, 10, 0, 0), ins(0x07, 3, 0, 0, int32(-family.size)), ins(0xb4, 4, 0, 0, int32(family.size)),
			ins(0x85, 0, 0, 0, 26), ins(0x18, 1, 1, 0, int32(family.fd)), ins(0, 0, 0, 0, 0),
			ins(0xbf, 2, 10, 0, 0), ins(0x07, 2, 0, 0, int32(-family.size-4)), ins(0x62, 2, 0, 0, int32(family.size*8)),
			ins(0x85, 0, 0, 0, 1), ins(0x15, 0, 0, 1, 0), ins(0x44, 8, 0, 0, 1))
	}
	return append(b, ins(0x44, 8, 0, 0, 2), ins(0xb7, 0, 0, 0, 1), ins(0x55, 8, 0, 1, 2), ins(0xb7, 0, 0, 0, 0), ins(0x95, 0, 0, 0, 0))
}
func loadReference(instructions []bpfInstruction) (int, error) {
	var b bytes.Buffer
	if err := binary.Write(&b, binary.NativeEndian, instructions); err != nil {
		return -1, err
	}
	code := b.Bytes()
	license := []byte("GPL\x00")
	defer pinBytes(code, license)()
	a := make([]byte, 72)
	put32(a, 0, unix.BPF_PROG_TYPE_CGROUP_SKB)
	put32(a, 4, uint32(len(instructions)))
	put64(a, 8, ptr64(code))
	put64(a, 16, ptr64(license))
	fd, err := bpfCall(unix.BPF_PROG_LOAD, a)
	runtime.KeepAlive(code)
	runtime.KeepAlive(license)
	return fd, err
}
func verifyProgram(id uint32, p policy, ingress bool) error {
	fd, err := bpfFD(unix.BPF_PROG_GET_FD_BY_ID, id)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	actual, err := inspectProgram(fd)
	if err != nil {
		return err
	}
	map4, map6 := -1, -1
	for _, id := range actual.maps {
		m, err := bpfFD(unix.BPF_MAP_GET_FD_BY_ID, id)
		if err != nil {
			return err
		}
		defer unix.Close(m)
		bits, err := verifyAllowMap(m, p)
		if err != nil {
			return err
		}
		if bits == 32 {
			if map4 >= 0 {
				return errFenceBPFPolicy
			}
			map4 = m
		} else {
			if map6 >= 0 {
				return errFenceBPFPolicy
			}
			map6 = m
		}
	}
	want4, want6 := false, false
	for _, r := range p.Egress {
		a, _ := netip.ParseAddr(r.Addr)
		if a.Is4() {
			want4 = true
		} else {
			want6 = true
		}
	}
	if want4 != (map4 >= 0) || want6 != (map6 >= 0) {
		return errFenceBPFPolicy
	}
	referenceFD, err := loadReference(firewallInstructions(map4, map6, ingress))
	if err != nil {
		return err
	}
	defer unix.Close(referenceFD)
	reference, err := inspectProgram(referenceFD)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual.code, reference.code) {
		return errFenceBPFPolicy
	}
	return nil
}
func verifyCgroupBPF(fd int, p policy) error {
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		return errFenceBPFUnsupported
	}
	for _, hook := range []uint32{unix.BPF_CGROUP_INET_INGRESS, unix.BPF_CGROUP_INET_EGRESS} {
		id, err := cgroupProgram(fd, hook)
		if err != nil {
			return classifyBPFError(err)
		}
		if err = verifyProgram(id, p, hook == unix.BPF_CGROUP_INET_INGRESS); err != nil {
			return classifyBPFError(err)
		}
		after, err := cgroupProgram(fd, hook)
		if err != nil {
			return classifyBPFError(err)
		}
		if after != id {
			return errFenceBPFPolicy
		}
	}
	return nil
}
