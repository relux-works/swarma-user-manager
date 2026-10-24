//go:build linux

package linuxos

import (
	"context"
	"errors"
	"os/user"
	"strconv"
)

// NSS is the host's trusted Go/libc directory-service adapter. Lookups are
// collision/identity observations only, never proof of journal ownership.
type NSS struct{}

func (NSS) UIDExists(ctx context.Context, id uint32) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	_, e := user.LookupId(number(id))
	if e == nil {
		return true, nil
	}
	var missing user.UnknownUserIdError
	if errors.As(e, &missing) {
		return false, nil
	}
	return false, e
}
func (NSS) GIDExists(ctx context.Context, id uint32) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	_, e := user.LookupGroupId(number(id))
	if e == nil {
		return true, nil
	}
	var missing user.UnknownGroupIdError
	if errors.As(e, &missing) {
		return false, nil
	}
	return false, e
}
func (NSS) NameExists(ctx context.Context, name string) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	_, e := user.Lookup(name)
	if e == nil {
		return true, nil
	}
	var missing user.UnknownUserError
	if errors.As(e, &missing) {
		return false, nil
	}
	return false, e
}
func (NSS) UID(ctx context.Context, name string) (uint32, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	u, e := user.Lookup(name)
	if e != nil {
		return 0, e
	}
	n, e := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(n), e
}
