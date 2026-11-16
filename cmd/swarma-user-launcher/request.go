//go:build linux

package main

import (
	"io"

	"github.com/relux-works/swarma-user-manager/internal/launch"
	"github.com/relux-works/swarma-user-manager/internal/manager"
)

// readRequest bounds launcher intake to the 80 KiB launch-op/1 ceiling.
func readRequest(src io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(src, launch.MaxLaunchRequest+1))
	if e != nil {
		return nil, &manager.Failure{Code: "request_invalid"}
	}
	if len(b) > launch.MaxLaunchRequest {
		return nil, &manager.Failure{Code: "request_too_large"}
	}
	return b, nil
}
