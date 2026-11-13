//go:build linux

package slotd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

func t19StandInAdmission(host, requested string) error {
	if host != "rt-stations" || requested != host {
		return errors.New("stand-in listener is permitted only on exactly rt-stations; never on stations1")
	}
	return nil
}

// Operator-only local stand-in, separate from the installed-daemon harness.
// It neither opens a wallet file nor reads/sends an application byte.
func runT19StandIn(args []string) int {
	fs := flag.NewFlagSet("slotd-t19-wallet-standin", flag.ContinueOnError)
	host := fs.String("host", "", "rt-stations only")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	fail := func(e error) int { fmt.Fprintln(os.Stderr, "T19 wallet stand-in:", e); return 1 }
	actual, err := os.Hostname()
	if err != nil {
		return fail(err)
	}
	if err = t19StandInAdmission(actual, *host); err != nil {
		return fail(err)
	}
	if err = t19RealHostAdmission(os.Geteuid(), actual, *host, t19ReadMarker); err != nil {
		return fail(err)
	}
	// Root creates only a previously absent directory. An existing wallet view is
	// never adopted, chmodded, unlinked or replaced by this helper.
	if err = os.Mkdir(walletSocketDir, 0755); err != nil {
		return fail(err)
	}
	var dir unix.Stat_t
	if err = unix.Lstat(walletSocketDir, &dir); err != nil {
		return fail(err)
	}
	defer func() {
		var current unix.Stat_t
		if unix.Lstat(walletSocketDir, &current) == nil && stamp(current) == stamp(dir) {
			if e := os.Remove(walletSocketDir); e != nil {
				fmt.Fprintln(os.Stderr, e)
			}
		}
	}()
	if err = os.Chmod(walletSocketDir, 0755); err != nil {
		return fail(err)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: t19WalletSock, Net: "unix"})
	if err != nil {
		return fail(err)
	}
	l.SetUnlinkOnClose(false)
	var socket unix.Stat_t
	if err = unix.Lstat(t19WalletSock, &socket); err != nil {
		l.Close()
		return fail(err)
	}
	defer func() {
		l.Close()
		var current unix.Stat_t
		if unix.Lstat(t19WalletSock, &current) == nil && stamp(current) == stamp(socket) {
			if e := os.Remove(t19WalletSock); e != nil {
				fmt.Fprintln(os.Stderr, e)
			}
		}
	}()
	if err = os.Chown(t19WalletSock, 0, 210101); err != nil {
		return fail(err)
	}
	if err = os.Chmod(t19WalletSock, 0660); err != nil {
		return fail(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); l.Close() }()
	fmt.Fprintln(os.Stderr, "STAND_IN: root:swarma-wallet-peer(210101) 0660 listening; no wallet RPC or funds")
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return 0
			}
			return fail(e)
		}
		c.Close()
	}
}
