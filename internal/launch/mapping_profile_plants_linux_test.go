//go:build linux

package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mappingProfilePlant struct {
	name, source, before, after, test, assertion, control, tags string
	pattern                                                     string
}

func assertMappingProfilePlant(t *testing.T, plant mappingProfilePlant) {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(directory, plant.source)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(source), plant.before) != 1 {
		t.Fatal("lab plant predicate is not unique")
	}
	scratch := t.TempDir()
	mutantPath := filepath.Join(scratch, plant.source)
	altered := strings.Replace(string(source), plant.before, plant.after, 1)
	if err := os.WriteFile(mutantPath, []byte(altered), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{sourcePath: mutantPath}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(scratch, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(overlayPath string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		arguments := []string{"test", "-p", "1", "-count=1", "-v", "-timeout=90s", "-run", "^(TestLabMapping(EnvironmentAndConfinement|Admission|ConfinementRefusal|OneStart)|TestProductionRejectsLabMapping|TestLaunchMappingGates|TestLaunchConfinementFilter)$"}
		if plant.pattern != "" {
			arguments[len(arguments)-1] = plant.pattern
		}
		if plant.tags != "" {
			arguments = append(arguments, "-tags", plant.tags)
		}
		if overlayPath != "" {
			arguments = append(arguments, "-overlay", overlayPath)
		}
		command := exec.CommandContext(ctx, "go", append(arguments, ".")...)
		command.Dir = directory
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		if err := command.Start(); err != nil {
			return "", err
		}
		t.Logf("plant=%s child_pid=%d overlay=%t", plant.name, command.Process.Pid, overlayPath != "")
		err := command.Wait()
		return output.String(), err
	}
	baseline, err := run("")
	if err != nil {
		t.Fatalf("lab plant baseline failed: %v\n%s", err, baseline)
	}
	output, err := run(overlayPath)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(output, "--- FAIL: "+plant.test) || !strings.Contains(output, plant.assertion) || !strings.Contains(output, "--- PASS: "+plant.control) {
		t.Fatalf("lab plant survived or failed outside its assertion: %v\n%s", err, output)
	}
	t.Logf("mutant=%s narrowed_to=%s killed_by=%s exit=1 baseline=0 control=%s:PASS", plant.name, plant.assertion, plant.test, plant.control)
}
