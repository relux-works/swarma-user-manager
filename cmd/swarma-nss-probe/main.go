//go:build linux && cgo

// A read-only status-aware files/systemd-module collector. It is not an account manager
// or qualification issuer. Only a parent with authenticated closure/exclusion may
// treat its output as evidence; stdout contains no password hashes.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/relux-works/swarma-user-manager/internal/nssprobe"
)

func main() {
	var files, systemd, rawLimit string
	switch {
	case len(os.Args) == 3:
		files, rawLimit = os.Args[1], os.Args[2]
	case len(os.Args) == 5 && os.Args[1] == "--files-systemd":
		rawLimit, files, systemd = os.Args[2], os.Args[3], os.Args[4]
	default:
		fail()
	}
	if files == "" || len(os.Args) == 5 && systemd == "" {
		fail()
	}
	for _, path := range []string{files, systemd} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			fail()
		}
	}
	limit, e := strconv.Atoi(rawLimit)
	if e != nil {
		fail()
	}
	var snapshot nssprobe.Snapshot
	if systemd == "" {
		snapshot, e = nssprobe.ReadFiles(files, limit)
	} else {
		snapshot, e = nssprobe.ReadFilesSystemd(files, systemd, limit)
	}
	if e != nil {
		fail()
	}
	if e = json.NewEncoder(os.Stdout).Encode(snapshot); e != nil {
		os.Exit(1)
	}
}
func fail() { fmt.Fprintln(os.Stderr, "nss_probe_unknown"); os.Exit(1) }
