//go:build linux

package slotd

// This is the single scalar expectation table for hosted fixtures and the
// observational real-host harness. Dynamic identity, inventory and unit/NFT
// expectations are derived by the same existing production/fixture validators.
// Wallet frame/restart assertions remain fixture-only; host use is connect-only.
type t19ExpectationTable struct {
	PathDenied                                        []string
	Hidden, Abstract, Connected, TCPDenied, UDPDenied string
	Families                                          map[string]string
	Tamper                                            map[string]string
	KeyRead, KeyWrite, KeyChmod                       string
}

func t19Expectations() t19ExpectationTable {
	return t19ExpectationTable{
		PathDenied: []string{"ENOENT", "EACCES"},
		Hidden:     "ENOENT", Abstract: "EPERM", Connected: "ok", TCPDenied: "timeout", UDPDenied: "EPERM",
		Families: map[string]string{"netlink": "EAFNOSUPPORT", "packet": "EAFNOSUPPORT", "unix": "ok", "inet": "ok", "inet6": "ok"},
		Tamper:   map[string]string{"prctl-no-new-privs-0": "EINVAL", "prctl-ambient-net-admin": "EPERM"},
		KeyRead:  "ok", KeyWrite: "EROFS", KeyChmod: "EROFS",
	}
}
