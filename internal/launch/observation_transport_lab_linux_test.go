//go:build linux && manager_lab

package launch

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/internal/manager"
	"golang.org/x/sys/unix"
)

func observationConnections(test *testing.T) (*net.UnixConn, *net.UnixConn) {
	test.Helper()
	var identifier [16]byte
	if _, err := rand.Read(identifier[:]); err != nil {
		test.Fatal(err)
	}
	address := &net.UnixAddr{Name: "@lab-observation-" + hex.EncodeToString(identifier[:]), Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		test.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, address)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { client.Close() })
	server, err := listener.AcceptUnix()
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { server.Close() })
	return client, server
}

func observationRequestFrame(raw []byte) []byte {
	frame := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	return frame
}

func observationTransportCase(test *testing.T, change func(*labObservationSource, *net.UnixConn, []byte), valid bool) {
	test.Helper()
	fixture, source, raw := observationFixture(test)
	clock, err := labBootNanos()
	if err != nil {
		test.Fatal(err)
	}
	source.now = func() (int64, error) { return clock, nil }
	client, connection := observationConnections(test)
	server := &labObservationServer{source: source}
	deadline, admitted := server.admit()
	if !admitted {
		test.Fatal("transport setup not admitted")
	}
	done := make(chan struct{})
	change(source, client, raw)
	go func() { defer close(done); server.handle(connection, deadline) }()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		test.Fatal(err)
	}
	response, err := io.ReadAll(client)
	<-done
	if valid {
		if err != nil || len(response) < 4 || int(binary.BigEndian.Uint32(response[:4])) != len(response)-4 {
			test.Fatal("valid native socket exchange refused", err)
		}
		var record labObservationResponse
		if manager.Strict(response[4:], &record) != nil || !record.Complete || record.Sequence != 2 {
			test.Fatal("socket response incomplete")
		}
	} else if len(response) != 0 {
		test.Fatal("forbidden transport produced a response")
	}
	counter, err := fixture.store.labCounter(source.binding.StoreGeneration)
	want := int64(1)
	if valid {
		want++
	}
	if err != nil || counter.Sequence != want {
		test.Fatal("transport rejection touched native sequence")
	}
	if fixture.seams.execs != 1 || len(fixture.debits()) != 1 {
		test.Fatal("transport reran native start")
	}
}

func validObservationWrite(test *testing.T, client *net.UnixConn, raw []byte) {
	test.Helper()
	if _, err := client.Write(observationRequestFrame(raw)); err != nil {
		test.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		test.Fatal(err)
	}
}

// Claim: real Unix peers and framing reach the fixture-clock collector; wrong peers, FDs and malformed/persistent input produce no sequence or second start, not native I/O timing qualification.
func TestLabObservationTransport(test *testing.T) {
	cases := map[string]func(*labObservationSource, *net.UnixConn, []byte){
		"foreign-peer": func(source *labObservationSource, client *net.UnixConn, raw []byte) {
			source.binding.DaemonUID++
			binding, err := manager.ObjectBytes(source.binding)
			if err != nil {
				test.Fatal(err)
			}
			if err := manager.WriteProtected(source.store.dir, "lab-observation-binding.json", binding, source.store.owner); err != nil {
				test.Fatal(err)
			}
			validObservationWrite(test, client, raw)
		},
		"root-not-daemon": func(source *labObservationSource, client *net.UnixConn, raw []byte) {
			source.binding.DaemonUID = 0
			validObservationWrite(test, client, raw)
		},
		"two-frames": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			frame := observationRequestFrame(raw)
			client.Write(append(frame, frame...))
			client.CloseWrite()
		},
		"trailing": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			client.Write(append(observationRequestFrame(raw), 0))
			client.CloseWrite()
		},
		"zero": func(_ *labObservationSource, client *net.UnixConn, _ []byte) {
			client.Write([]byte{0, 0, 0, 0})
			client.CloseWrite()
		},
		"oversize": func(_ *labObservationSource, client *net.UnixConn, _ []byte) {
			var frame [4]byte
			binary.BigEndian.PutUint32(frame[:], 4097)
			client.Write(frame[:])
			client.CloseWrite()
		},
		"truncated": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			frame := observationRequestFrame(raw)
			client.Write(frame[:len(frame)-1])
			client.CloseWrite()
		},
		"no-frame": func(_ *labObservationSource, client *net.UnixConn, _ []byte) { client.CloseWrite() },
		"no-eof": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			client.Write(observationRequestFrame(raw))
		},
		"ancillary": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			file, err := os.Open(os.DevNull)
			if err != nil {
				test.Fatal(err)
			}
			defer file.Close()
			if _, _, err := client.WriteMsgUnix(observationRequestFrame(raw), unix.UnixRights(int(file.Fd())), nil); err != nil {
				test.Fatal(err)
			}
			client.CloseWrite()
		},
		"selector": func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
			altered := append([]byte(`{"path":"fixture",`), raw[1:]...)
			validObservationWrite(test, client, altered)
		},
	}
	for name, change := range cases {
		test.Run(name, func(test *testing.T) {
			observationTransportCase(test, func(_ *labObservationSource, client *net.UnixConn, raw []byte) {
				validObservationWrite(test, client, raw)
			}, true)
			observationTransportCase(test, change, false)
		})
	}
}

// Claim: one server-wide slot includes unauthenticated connections; cooldown and regression refuse before any further native lock admission.
func TestLabObservationLoad(test *testing.T) {
	_, source, _ := observationFixture(test)
	now := int64(time.Second)
	source.now = func() (int64, error) { return now, nil }
	server := &labObservationServer{source: source, notBefore: now + int64(250*time.Millisecond), lastNow: now}
	if _, admitted := server.admit(); admitted {
		test.Fatal("startup cooldown bypassed")
	}
	now += int64(250 * time.Millisecond)
	if _, admitted := server.admit(); !admitted {
		test.Fatal("cooldown equality control refused")
	}
	if _, admitted := server.admit(); admitted {
		test.Fatal("concurrent observation admitted")
	}
	server.release()
	now += int64(250*time.Millisecond) - 1
	if _, admitted := server.admit(); admitted {
		test.Fatal("release cooldown bypassed")
	}
	now++
	if _, admitted := server.admit(); !admitted {
		test.Fatal("release equality control refused")
	}
	server.release()
	now--
	if _, admitted := server.admit(); admitted {
		test.Fatal("regressed clock admitted")
	}
	now += int64(time.Second)
	if _, admitted := server.admit(); admitted {
		test.Fatal("clock incident reopened")
	}
}

// Claim: the CLOCK_BOOTTIME watchdog closes an idle real connection at its original deadline and cancellation reaps the watchdog without touching native state.
func TestLabObservationBootDeadline(test *testing.T) {
	client, server := observationConnections(test)
	now, err := labBootNanos()
	if err != nil {
		test.Fatal(err)
	}
	stop, err := labObservationDeadline(server, now+int64(20*time.Millisecond))
	if err != nil {
		test.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [1]byte
	if count, err := client.Read(buffer[:]); count != 0 || err != io.EOF {
		test.Fatal("boottime deadline did not close connection", err)
	}
	stop()
	_, next := observationConnections(test)
	now, _ = labBootNanos()
	stop, err = labObservationDeadline(next, now+int64(time.Second))
	if err != nil {
		test.Fatal(err)
	}
	stop()
	if err := next.SetDeadline(time.Now().Add(time.Second)); err != nil {
		test.Fatal("cancel closed valid connection", err)
	}
}

// Claim: serialized native effects.lock contention refuses immediately instead of queuing; release admits the unchanged complete collector again.
func TestLabObservationLockPriority(test *testing.T) {
	fixture, source, request := observationFixture(test)
	unlock, err := fixture.store.Lock(context.Background(), 0)
	if err != nil {
		test.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		if _, err := source.observe(context.Background(), request, int64(3*time.Second)); err == nil {
			test.Error("observation bypassed native writer lock")
		}
	}()
	group.Wait()
	unlock()
	observeFixture(test, source, request)
}

// Claim: SO_PEERCRED accepts the actual nonroot Unix client only for its exact configured UID and rejects a different UID or a root daemon configuration.
func TestLabObservationKernelPeer(test *testing.T) {
	_, server := observationConnections(test)
	if err := labObservationPeer(server, int64(os.Getuid())); err != nil {
		test.Fatal("actual kernel peer control refused", err)
	}
	if err := labObservationPeer(server, int64(os.Getuid())+1); err == nil {
		test.Fatal("different kernel peer UID admitted")
	}
	if err := labObservationPeer(server, 0); err == nil {
		test.Fatal("root daemon configuration admitted")
	}
}

// Claim: the frame reader accepts exactly 4096 payload bytes and refuses 4097; these are transport preflights, not grammar-valid observation requests.
func TestLabObservationFrameLimit(test *testing.T) {
	for _, length := range []int{4096, 4097} {
		client, server := observationConnections(test)
		raw := make([]byte, length)
		if _, err := client.Write(observationRequestFrame(raw)); err != nil {
			test.Fatal(err)
		}
		if err := client.CloseWrite(); err != nil {
			test.Fatal(err)
		}
		actual, err := labObservationFrame(server)
		if length == 4096 && (err != nil || len(actual) != length) {
			test.Fatal("at-limit frame refused", err)
		}
		if length == 4097 && (err == nil || actual != nil) {
			test.Fatal("oversized frame admitted")
		}
	}
}

// Claim: the actual frame reader preserves exactly one payload and refuses trailing bytes even when a later JSON reader would independently reject them.
func TestLabObservationFrameEOF(test *testing.T) {
	for _, extra := range []bool{false, true} {
		client, server := observationConnections(test)
		frame := observationRequestFrame([]byte("fixture"))
		if extra {
			frame = append(frame, 0)
		}
		if _, err := client.Write(frame); err != nil {
			test.Fatal(err)
		}
		if err := client.CloseWrite(); err != nil {
			test.Fatal(err)
		}
		actual, err := labObservationFrame(server)
		if !extra && (err != nil || string(actual) != "fixture") {
			test.Fatal("exact frame control refused")
		}
		if extra && (err == nil || actual != nil) {
			test.Fatal("framing accepted trailing bytes")
		}
	}
}
