//go:build !linux

package pc2store

import "github.com/relux-works/swarma-user-manager/internal/pc2state"

type Store struct{}

func OpenInstalled(string) (*Store, error) { return nil, ErrUnavailable }
func (*Store) Close() error                { return nil }
func (*Store) Head() (Head, error)         { return Head{}, ErrUnavailable }
func (*Store) Inspect() (Report, error)    { return Report{}, ErrUnavailable }
func (*Store) Publish(Head, string, pc2state.Object) (Receipt, error) {
	return Receipt{}, ErrUnavailable
}
func (*Store) Reconcile(Head) (Receipt, error) { return Receipt{}, ErrUnavailable }
