package genjournal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

// Run implements the offline CLI. Ownership is unconditionally root in production.
func Run(args []string, out, errs io.Writer) int { return run(args, out, errs, production) }
func run(args []string, out, errs io.Writer, p policy) int {
	e := command(args, out, p)
	if e == nil {
		return 0
	}
	if r, ok := e.(*Refusal); ok {
		_ = json.NewEncoder(errs).Encode(r)
		return 1
	}
	fmt.Fprintln(errs, `{"Code":"journal_usage","Line":0}`)
	return 2
}
func command(args []string, out io.Writer, p policy) error {
	usage := func() error { return fmt.Errorf("usage") }
	if len(args) == 1 && args[0] == "token" {
		b := make([]byte, 16)
		if _, e := rand.Read(b); e != nil {
			return refuse("journal_entropy")
		}
		token := hex.EncodeToString(b)
		if token == "00000000000000000000000000000000" {
			return refuse("journal_entropy")
		}
		_, e := fmt.Fprintln(out, token)
		return e
	}
	if len(args) < 2 {
		return usage()
	}
	action, path := args[0], args[1]
	if action == "init" {
		if len(args) != 2 {
			return usage()
		}
		return initialize(path, p)
	}
	if action == "lock-writer" {
		if len(args) != 2 {
			return usage()
		}
		return waitWriterLocks(path, p)
	}
	if action == "intent" {
		if len(args) != 2 {
			return usage()
		}
		return makeIntent(path, p)
	}
	if len(args) < 4 {
		return usage()
	}
	seq, e := strconv.ParseInt(args[2], 10, 64)
	if e != nil {
		return refuse("journal_floor")
	}
	floor := Floor{seq, args[3]}
	if !validFloor(floor) {
		return refuse("journal_floor")
	}
	switch action {
	case "bytes":
		if len(args) != 4 {
			return usage()
		}
		f, e := os.Open(path)
		if e != nil {
			return refuse("journal_io")
		}
		defer f.Close()
		v, e := Verify(f, floor)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "rollback-genesis-locked":
		if len(args) != 4 || floor != (Floor{0, ZeroHash}) {
			return usage()
		}
		return rollbackGenesis(path, p)
	case "verify":
		if len(args) != 4 {
			return usage()
		}
		v, e := inspect(context.Background(), path, floor, p)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	case "finish-intent":
		if len(args) != 4 {
			return usage()
		}
		v, e := finishIntent(path, floor, p)
		if e != nil {
			return e
		}
		// The parent's inherited open-file descriptions are unlocked before diagnostic stdout can block.
		if syscall.Flock(9, syscall.LOCK_UN) != nil || syscall.Flock(8, syscall.LOCK_UN) != nil {
			return refuse("journal_lock")
		}
		return json.NewEncoder(out).Encode(v)
	case "clear-intent":
		if len(args) != 4 {
			return usage()
		}
		return clearIntent(path, floor, p)
	case "append-locked":
		if len(args) != 10 {
			return usage()
		}
		nums := make([]int64, 3)
		for i := range nums {
			n, e := strconv.ParseInt(args[4+i], 10, 64)
			if e != nil {
				return refuse("journal_station_range")
			}
			nums[i] = n
		}
		return appendRecord(path, floor, nums[0], nums[1], nums[2], args[7], args[8], args[9], p)
	case "verify-locked":
		if len(args) != 4 {
			return usage()
		}
		d, e := openDirectory(path, p, true)
		if e != nil {
			return e
		}
		defer d.file.Close()
		if e = requireWriterLocks(d); e != nil {
			return e
		}
		j, e := d.open("journal", 0)
		if e != nil {
			return e
		}
		defer j.Close()
		v, e := Verify(j, floor)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(v)
	default:
		return usage()
	}
}

// WholeSecondUTC supplies a public timestamp, never an ordering authority.
func WholeSecondUTC() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }
