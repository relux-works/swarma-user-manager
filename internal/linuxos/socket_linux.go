//go:build linux

package linuxos

import (
	"context"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// UnixSockets combines the trusted /proc/net/unix table with a kernel UNIX_DIAG
// dump containing UNIX_DIAG_UID. Scope is the current network namespace; require
// NamespaceCoverage as a separate gate. A names-only listing cannot return clean.
func (p *Proc) UnixSockets(ctx context.Context, uid uint32, max int) Result {
	if uid == 0 || max <= 0 {
		return result("unix_sockets", nil, refusal("inventory_unknown", "socket_policy", nil))
	}
	// /proc/net is a magic symlink. Use the real current-PID net directory instead.
	dir, e := child(p.root, strconv.Itoa(unix.Getpid()), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return result("unix_sockets", nil, e)
	}
	net, e := child(dir, "net", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	e = errors.Join(e, dir.Close())
	if e != nil {
		if net != nil {
			net.Close()
		}
		return result("unix_sockets", nil, e)
	}
	b, e := p.read(net, "unix")
	e = errors.Join(e, net.Close())
	if e != nil {
		return result("unix_sockets", nil, e)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 || !strings.Contains(lines[0], "Inode") {
		return result("unix_sockets", nil, refusal("inventory_unknown", "socket_table", nil))
	}
	if len(lines) > max+1 {
		return result("unix_sockets", nil, refusal("inventory_limit", "socket_table", nil))
	}
	// The two snapshots may race. The diagnostic dump is authoritative for UID,
	// but a table inode omitted from it makes the observation incomplete.
	table := map[uint32]bool{}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 7 {
			return result("unix_sockets", nil, refusal("inventory_unknown", "socket_row", nil))
		}
		n, e := strconv.ParseUint(f[6], 10, 32)
		if e != nil {
			return result("unix_sockets", nil, e)
		}
		table[uint32(n)] = true
	}
	objects, seen, e := unixDiagnostic(ctx, uid, max)
	if e == nil {
		for inode := range table {
			if !seen[inode] {
				e = refusal("inventory_unknown", "socket_snapshot_changed", nil)
				break
			}
		}
	}
	return result("unix_sockets", objects, e)
}
func unixDiagnostic(ctx context.Context, uid uint32, max int) (objects []Object, seen map[uint32]bool, err error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, nil, refusal("budget_invalid", "socket_deadline", nil)
	}
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if e != nil {
		return nil, nil, e
	}
	defer func() { err = errors.Join(err, unix.Close(fd)) }()
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return nil, nil, e
	}
	req := make([]byte, 40)
	binary.NativeEndian.PutUint32(req[0:4], 40)
	binary.NativeEndian.PutUint16(req[4:6], 20)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(req[8:12], 1)
	req[16] = unix.AF_UNIX
	binary.NativeEndian.PutUint32(req[20:24], ^uint32(0))
	binary.NativeEndian.PutUint32(req[28:32], 0x41)
	binary.NativeEndian.PutUint32(req[32:36], ^uint32(0))
	binary.NativeEndian.PutUint32(req[36:40], ^uint32(0))
	if e = unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return nil, nil, e
	}
	seen = map[uint32]bool{}
	buffer := make([]byte, 1<<16)
	for {
		if e = ctx.Err(); e != nil {
			return objects, seen, e
		}
		wait := 100 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			if left := time.Until(deadline); left < wait {
				wait = left
			}
		}
		if wait <= 0 {
			return objects, seen, context.DeadlineExceeded
		}
		tv := unix.NsecToTimeval(wait.Nanoseconds())
		if e = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); e != nil {
			return objects, seen, e
		}
		n, _, flags, from, e := unix.Recvmsg(fd, buffer, nil, 0)
		if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return objects, seen, e
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return objects, seen, refusal("inventory_unknown", "netlink_origin", nil)
		}
		for offset := 0; offset < n; {
			if n-offset < 16 {
				return objects, seen, refusal("inventory_unknown", "netlink_header", nil)
			}
			data := buffer[offset:n]
			length := int(binary.NativeEndian.Uint32(data[:4]))
			if length < 16 || length > len(data) {
				return objects, seen, refusal("inventory_unknown", "netlink_length", nil)
			}
			kind := binary.NativeEndian.Uint16(data[4:6])
			f := binary.NativeEndian.Uint16(data[6:8])
			seq := binary.NativeEndian.Uint32(data[8:12])
			if seq != 1 || f&unix.NLM_F_DUMP_INTR != 0 {
				return objects, seen, refusal("inventory_unknown", "netlink_dump", nil)
			}
			body := data[16:length]
			switch kind {
			case unix.NLMSG_DONE:
				if len(body) >= 4 && int32(binary.NativeEndian.Uint32(body[:4])) != 0 {
					return objects, seen, refusal("inventory_unknown", "netlink_done_error", nil)
				}
				return objects, seen, nil
			case unix.NLMSG_ERROR, unix.NLMSG_OVERRUN:
				return objects, seen, refusal("inventory_unknown", "netlink_error", nil)
			case 20:
				object, matched, inode, e := parseUnixDiagnostic(body, uid)
				if e != nil {
					return objects, seen, e
				}
				if seen[inode] {
					return objects, seen, refusal("inventory_unknown", "duplicate_socket", nil)
				}
				seen[inode] = true
				if matched {
					objects = append(objects, object)
				}
				if len(seen) > max {
					return objects, seen, refusal("inventory_limit", "netlink_dump", nil)
				}
			default:
				return objects, seen, refusal("inventory_unknown", "netlink_type", nil)
			}
			offset += (length + 3) &^ 3
		}
	}
}
func parseUnixDiagnostic(body []byte, uid uint32) (Object, bool, uint32, error) {
	out := Object{Class: "unix_sockets"}
	if len(body) < 16 || body[0] != unix.AF_UNIX {
		return out, false, 0, refusal("inventory_unknown", "unix_diag", nil)
	}
	inode := binary.NativeEndian.Uint32(body[4:8])
	out.Inode = uint64(inode)
	found := false
	for offset := 16; offset < len(body); {
		if len(body)-offset < 4 {
			return out, false, inode, refusal("inventory_unknown", "unix_attr", nil)
		}
		n := int(binary.NativeEndian.Uint16(body[offset : offset+2]))
		kind := binary.NativeEndian.Uint16(body[offset+2 : offset+4])
		if n < 4 || offset+n > len(body) {
			return out, false, inode, refusal("inventory_unknown", "unix_attr_length", nil)
		}
		value := body[offset+4 : offset+n]
		if kind == 7 {
			if len(value) != 4 || found {
				return out, false, inode, refusal("inventory_unknown", "unix_uid", nil)
			}
			out.UID = binary.NativeEndian.Uint32(value)
			found = true
		}
		if kind == 0 {
			out.Name = strings.TrimRight(string(value), "\x00")
		}
		offset += (n + 3) &^ 3
	}
	if !found {
		return out, false, inode, refusal("inventory_unknown", "unix_uid_missing", nil)
	}
	return out, out.UID == uid, inode, nil
}
