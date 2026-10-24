//go:build linux && cgo

// A read-only status-aware files-module collector. It is not an account manager
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
	if len(os.Args) != 3 || !filepath.IsAbs(os.Args[1]) || filepath.Clean(os.Args[1]) != os.Args[1] {
		fail()
	}
	limit, e := strconv.Atoi(os.Args[2])
	if e != nil {
		fail()
	}
	snapshot, e := nssprobe.ReadFiles(os.Args[1], limit)
	if e != nil {
		fail()
	}
	if e = json.NewEncoder(os.Stdout).Encode(snapshot); e != nil {
		os.Exit(1)
	}
}
func fail() { fmt.Fprintln(os.Stderr, "nss_probe_unknown"); os.Exit(1) }
