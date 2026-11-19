//go:build linux

package manager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// An owned child witnesses write/file-fsync/close/rename/directory-fsync order.
// Injected EIO must reach the writer's refusal, not an unrelated setup failure;
// this is syscall ordering/error evidence, not power-loss or root qualification.
func TestProjectionAtomicSyscallTrace(t *testing.T) {
	tool, err := exec.LookPath("strace")
	if err != nil {
		t.Fatal("identity atomic syscall tests require strace", err)
	}
	for _, mode := range []string{"valid", "file-sync-EIO", "directory-sync-EIO"} {
		t.Run(mode, func(t *testing.T) {
			waitIdentityPlantLoad(t)
			root := t.TempDir()
			tracePath := filepath.Join(root, "syscalls.log")
			arguments := []string{"-f", "-qq", "-yy", "-e", "trace=write,fsync,close,renameat", "-o", tracePath}
			if mode != "valid" {
				ordinal := 4
				if mode == "directory-sync-EIO" {
					ordinal = 5
				}
				arguments = append(arguments, "-e", fmt.Sprintf("inject=fsync:error=EIO:when=%d", ordinal))
			}
			arguments = append(arguments, os.Args[0], "-test.run=^TestProjectionAtomicTraceChild$", "-test.v", "-test.timeout=60s")
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, tool, arguments...)
			command.Env = append(os.Environ(), "SWARMA_IDENTITY_TRACE_ROOT="+root, "SWARMA_IDENTITY_TRACE_MODE="+mode)
			output, err := command.CombinedOutput()
			if command.ProcessState == nil {
				t.Fatalf("trace process could not start: %v", err)
			}
			t.Logf("strace child pid=%d mode=%s output=%s", command.ProcessState.Pid(), mode, output)
			if err != nil || !strings.Contains(string(output), "--- PASS: TestProjectionAtomicTraceChild") {
				t.Fatalf("atomic trace child failed: %v %s", err, output)
			}
			raw, err := os.ReadFile(tracePath)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "valid" {
				if !strings.Contains(string(raw), "INJECTED") || !strings.Contains(string(output), "observed projection sync refusal") {
					t.Fatal("sync EIO plant not observed")
				}
				return
			}
			written, synced, closed, renamed, directorySynced := -1, -1, -1, -1, -1
			for index, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, "/.write-") {
					if strings.Contains(line, "write(") {
						written = index
					}
					if strings.Contains(line, "fsync(") {
						synced = index
					}
					if strings.Contains(line, "close(") {
						closed = index
					}
				}
				if strings.Contains(line, "renameat(") && strings.Contains(line, "\"identities.json\"") {
					renamed = index
				}
				if renamed >= 0 && strings.Contains(line, "fsync(") && strings.Contains(line, "<"+root+">") {
					directorySynced = index
				}
			}
			if written < 0 || synced <= written || closed <= synced || renamed <= closed || directorySynced <= renamed {
				t.Fatalf("atomic publication syscall order missing: write=%d sync=%d close=%d rename=%d directory-sync=%d\n%s", written, synced, closed, renamed, directorySynced, raw)
			}
		})
	}
}

func TestProjectionAtomicTraceChild(t *testing.T) {
	root := os.Getenv("SWARMA_IDENTITY_TRACE_ROOT")
	if root == "" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	journalPath := filepath.Join(root, "journal")
	if err := os.Mkdir(journalPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := provisionStore(journalPath, 30000, uint32(os.Getuid()), root); err != nil {
		t.Fatal("trace setup", err)
	}
	store, err := openStore(journalPath, uint32(os.Getuid()), root)
	if err != nil {
		t.Fatal("trace setup", err)
	}
	defer store.Close()
	state, err := store.Load()
	if err != nil {
		t.Fatal("trace setup", err)
	}
	err = store.Identities(state, genjournal.View{Tail: genjournal.Floor{Hash: genjournal.ZeroHash}}, "trusted")
	mode := os.Getenv("SWARMA_IDENTITY_TRACE_MODE")
	if mode == "valid" {
		if err != nil {
			t.Fatal("atomic write control", err)
		}
		return
	}
	if errorCode(err) != "state_unavailable" {
		t.Fatal("injected sync acknowledged", err)
	}
	if mode == "file-sync-EIO" {
		if _, err := os.Stat(filepath.Join(root, "identities.json")); !os.IsNotExist(err) {
			t.Fatal("failed file sync published projection", err)
		}
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".write-") {
			t.Fatal("failed publication leaked temp")
		}
	}
	t.Log("observed projection sync refusal")
}
