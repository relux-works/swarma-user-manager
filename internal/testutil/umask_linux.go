package testutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"testing"
)

func Umasks(t *testing.T, check func(*testing.T)) {
	t.Helper()
	const variable = "SWARMA_TEST_CREATION_UMASK"
	if value := os.Getenv(variable); value != "" {
		mask, err := strconv.ParseUint(value, 8, 9)
		if err != nil {
			t.Fatal(err)
		}
		previous := syscall.Umask(int(mask))
		defer syscall.Umask(previous)
		check(t)
		return
	}
	name := t.Name()
	for _, mask := range []int{0022, 0077, 0002} {
		t.Run(fmt.Sprintf("%04o", mask), func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(name)+"$", "-test.v", "-test.timeout=90s")
			command.Env = append(os.Environ(), fmt.Sprintf("%s=%04o", variable, mask))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("writer under umask %04o: %v\n%s", mask, err, output)
			}
		})
	}
}

func Mode(t *testing.T, path string, expected uint32) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := info.Sys().(*syscall.Stat_t).Mode & 07777
	if actual != expected {
		t.Fatalf("%s mode %04o, want %04o", path, actual, expected)
	}
}

func Modes(t *testing.T, root string, directory, file uint32) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			Mode(t, path, directory)
		} else if entry.Type().IsRegular() {
			Mode(t, path, file)
		} else {
			t.Fatalf("unexpected object type at %s: %v", path, entry.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
