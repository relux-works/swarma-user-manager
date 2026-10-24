//go:build linux

package linuxos

import "os/exec"

const accountOutputLimit = 4096
const accountTruncation = "\n[truncated]"

// AccountToolDiagnostic is protected diagnostic data, never a public error
// string. ExitStatus is -1 when no normal process exit status is available.
// Each stream includes its truncation marker within the 4096-byte bound.
type AccountToolDiagnostic struct {
	ExitStatus     int
	Stderr, Stdout string
}

type accountOutput struct {
	data      []byte
	truncated bool
}

// Always drain the child: a full capture must not change its exit behavior.
func (b *accountOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := accountOutputLimit - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (b *accountOutput) String() string {
	if b.truncated {
		return string(b.data[:accountOutputLimit-len(accountTruncation)]) + accountTruncation
	}
	return string(b.data)
}

func runAccountCommand(cmd *exec.Cmd) error {
	var stdout, stderr accountOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if e := cmd.Run(); e != nil {
		status := -1
		if cmd.ProcessState != nil {
			status = cmd.ProcessState.ExitCode()
		}
		return &Error{Code: "backend_failed", Operation: "account_tool", Cause: e,
			Tool: &AccountToolDiagnostic{ExitStatus: status, Stderr: stderr.String(), Stdout: stdout.String()}}
	}
	return nil
}
