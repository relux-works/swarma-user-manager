//go:build linux && !manager_lab

package launch

import "github.com/relux-works/swarma-user-manager/tools/genjournal"

type labStartCheck func(string, int64) bool

func (Launcher) admitLabStart(Request, *launchMapping, approvedExecutor, string, int64, genjournal.Floor) (labStartCheck, error) {
	return nil, nil
}
