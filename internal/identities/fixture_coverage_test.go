package identities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixtureCoverageFunction struct {
	Name, File string
	Start, End int
}

type fixtureCoverageBranch struct {
	ID, Function, File string
	Line               int
	End                int
	UnwitnessedTrue    string
}

type fixtureCoverageEdit struct {
	Start, End int
	Text       string
}

// Only manifest rows supply inputs. Typed passes additionally exercise the
// standalone validation/lookup contracts, never a substitute for wire admission.
func TestSharedFixtureCoverageRows(t *testing.T) {
	if os.Getenv("SWARMA_SHARED_FIXTURE_COVERAGE_CHILD") != "1" {
		t.Skip("executed exclusively by TestSharedFixtureCoverageGate")
	}
	manifest := fixtures(t)
	sharedView := fixtureJournal(t, manifest.Journal, manifest.JournalHead)
	for _, example := range manifest.Cases {
		if example.Check == "custody" {
			continue
		}
		t.Run(example.Name, func(t *testing.T) {
			view := sharedView
			if example.Check == "service" {
				view = fixtureJournal(t, example.Journal, example.JournalHead)
			}
			uid, generation := manifest.UID, manifest.Generation
			if example.UID != nil {
				uid = *example.UID
			}
			if example.Generation != "" {
				generation = example.Generation
			}
			raw := fixtureBytes(t, example.File)
			document, err := Decode(raw, view.Tail.Hash)
			switch example.Check {
			case "decode":
			case "service":
				if err != nil {
					t.Fatal("shared service must decode", err)
				}
				var account Account
				account, err = fixtureServicePrincipal(document, view, uid)
				if err == nil && example.Verdict == "accept" && (example.Principal == nil || *example.Principal != (fixturePrincipal{account.UID, account.Generation, account.Name})) {
					t.Fatal("shared principal differs")
				}
			case "transition":
				if err != nil {
					t.Fatal("shared transition must decode", err)
				}
				previous, previousErr := Decode(fixtureBytes(t, example.Previous), view.Tail.Hash)
				if previousErr != nil {
					t.Fatal(previousErr)
				}
				err = ValidateTransition(previous, document)
			default:
				t.Fatal("unregistered shared operation", example.Check)
			}
			if example.Verdict == "accept" && err != nil || example.Verdict != "accept" && !errors.Is(err, ErrMismatch) {
				t.Fatalf("shared verdict differs: %s: %v", example.Verdict, err)
			}
			var typed Document
			if json.Unmarshal(raw, &typed) == nil {
				validation := typed.Validate()
				_, serviceErr := typed.Service(uid, generation)
				_, principalErr := fixtureServicePrincipal(typed, view, uid)
				transitionErr := ValidateTransition(typed, typed)
				if validation != nil && (!errors.Is(serviceErr, ErrMismatch) || !errors.Is(principalErr, ErrMismatch) || !errors.Is(transitionErr, ErrMismatch)) {
					t.Fatal("invalid shared typed document admitted")
				}
				if validation == nil && transitionErr != nil {
					t.Fatal("valid shared self-transition refused", transitionErr)
				}
			}
		})
	}
}

func copyFixtureCoverageTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0644)
	})
	if err != nil {
		t.Fatal("coverage checkout copy", err)
	}
}

func prepareFixtureCoverage(t *testing.T, root string) ([]fixtureCoverageFunction, []fixtureCoverageBranch) {
	t.Helper()
	lookupPath := filepath.Join(root, "internal/identities/identities_test.go")
	raw, err := os.ReadFile(lookupPath)
	if err != nil {
		t.Fatal(err)
	}
	positions := token.NewFileSet()
	parsed, err := parser.ParseFile(positions, lookupPath, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	extracted := false
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "fixtureServicePrincipal" {
			continue
		}
		start, end := positions.Position(function.Pos()), positions.Position(function.End())
		lookup := "package identities\n\nimport \"github.com/relux-works/swarma-user-manager/tools/genjournal\"\n" + strings.Repeat("\n", start.Line-4) + string(raw[start.Offset:end.Offset]) + "\n"
		if err := os.WriteFile(filepath.Join(root, "internal/identities/fixture_lookup.go"), []byte(lookup), 0644); err != nil {
			t.Fatal(err)
		}
		raw = append(append(append([]byte{}, raw[:start.Offset]...), []byte(strings.Repeat("\n", end.Line-start.Line))...), raw[end.Offset:]...)
		extracted = true
		break
	}
	if !extracted {
		t.Fatal("reference service lookup not found")
	}
	if err := os.WriteFile(lookupPath, raw, 0644); err != nil {
		t.Fatal(err)
	}
	var functions []fixtureCoverageFunction
	var branches []fixtureCoverageBranch
	files := []string{"identities.go", "fixture_lookup.go"}
	if runtime.GOOS == "linux" {
		files = append(files, "protected_linux.go")
	}
	for _, file := range files {
		path := filepath.Join(root, "internal/identities", file)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, file, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		original := file
		if file == "fixture_lookup.go" {
			original = "identities_test.go"
		}
		var edits []fixtureCoverageEdit
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := function.Name.Name
			if name != "Decode" && name != "Validate" && name != "ValidateTransition" && name != "Service" && name != "fixtureServicePrincipal" && name != "Read" {
				continue
			}
			if function.Recv != nil {
				name = "Document." + name
			}
			start, end := positions.Position(function.Pos()), positions.Position(function.End())
			functions = append(functions, fixtureCoverageFunction{name, original, start.Line, end.Line})
			ast.Inspect(function.Body, func(node ast.Node) bool {
				conditional, ok := node.(*ast.IfStmt)
				if !ok {
					return true
				}
				position := positions.Position(conditional.If)
				id := fmt.Sprintf("%s:%d:%d", original, position.Line, position.Column)
				left, right := positions.Position(conditional.Cond.Pos()).Offset, positions.Position(conditional.Cond.End()).Offset
				branch := fixtureCoverageBranch{ID: id, Function: name, File: original, Line: position.Line, End: positions.Position(conditional.Body.End()).Line}
				if original == "protected_linux.go" && name == "Read" {
					switch string(raw[left:right]) {
					case "!errors.Is(err, syscall.ENODATA)":
						branch.UnwitnessedTrue = "xattr refusal requires ACL/capability or syscall fault, not portable custody metadata"
					case "readErr != nil || closeErr != nil":
						branch.UnwitnessedTrue = "read/close failure requires syscall fault after successful protected open"
					}
				}
				branches = append(branches, branch)
				edits = append(edits, fixtureCoverageEdit{left, right, "fixtureCoverageBranchHit(" + strconv.Quote(id) + ", " + string(raw[left:right]) + ")"})
				return true
			})
		}
		sort.Slice(edits, func(left, right int) bool { return edits[left].Start > edits[right].Start })
		for _, edit := range edits {
			raw = append(append(append([]byte{}, raw[:edit.Start]...), []byte(edit.Text)...), raw[edit.End:]...)
		}
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	expectedFunctions := 5
	if runtime.GOOS == "linux" {
		expectedFunctions++
	}
	if len(functions) != expectedFunctions || len(branches) == 0 {
		t.Fatal("coverage target set differs", functions)
	}
	const probe = `package identities
var fixtureBranchHits = map[string][2]uint64{}
func fixtureCoverageBranchHit(id string, value bool) bool {
    counts := fixtureBranchHits[id]
    if value { counts[1]++ } else { counts[0]++ }
    fixtureBranchHits[id] = counts
    return value
}
`
	const reporter = `package identities
import ("encoding/json"; "os"; "testing")
func TestMain(main *testing.M) {
    exit := main.Run()
    raw, err := json.Marshal(fixtureBranchHits)
    if err != nil || os.WriteFile(os.Getenv("SWARMA_SHARED_FIXTURE_BRANCH_REPORT"), raw, 0600) != nil { os.Exit(2) }
    os.Exit(exit)
}
`
	for file, source := range map[string]string{"fixture_branches.go": probe, "fixture_branches_test.go": reporter} {
		if err := os.WriteFile(filepath.Join(root, "internal/identities", file), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return functions, branches
}

func verifyFixtureCoverage(profile []byte, functions []fixtureCoverageFunction, branches []fixtureCoverageBranch, hits map[string][2]uint64) ([]string, error) {
	var output []string
	for _, function := range functions {
		statements := 0
		coveredStatements := 0
		for _, line := range strings.Split(string(profile), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 3 {
				continue
			}
			separator := strings.LastIndex(fields[0], ":")
			if separator < 0 {
				return nil, fmt.Errorf("malformed coverage block %q", line)
			}
			file := filepath.Base(fields[0][:separator])
			if file == "fixture_lookup.go" {
				file = "identities_test.go"
			}
			var firstLine, firstColumn, lastLine, lastColumn int
			if _, err := fmt.Sscanf(fields[0][separator+1:], "%d.%d,%d.%d", &firstLine, &firstColumn, &lastLine, &lastColumn); err != nil {
				return nil, err
			}
			if file != function.File || firstLine < function.Start || firstLine > function.End {
				continue
			}
			count, err := strconv.Atoi(fields[1])
			if err != nil {
				return nil, err
			}
			statements += count
			if fields[2] == "0" && count > 0 {
				declared := false
				for _, branch := range branches {
					if branch.Function == function.Name && branch.File == file && branch.UnwitnessedTrue != "" && firstLine >= branch.Line && lastLine <= branch.End {
						declared = true
					}
				}
				if declared {
					continue
				}
				return nil, fmt.Errorf("uncovered statement/refusal branch %s:%d in %s", function.File, firstLine, function.Name)
			}
			coveredStatements += count
		}
		if statements == 0 {
			return nil, fmt.Errorf("missing coverage %s:%d in %s", function.File, function.Start, function.Name)
		}
		outcomes := 0
		coveredOutcomes := 0
		for _, branch := range branches {
			if branch.Function != function.Name {
				continue
			}
			for outcome, count := range hits[branch.ID] {
				outcomes++
				if count == 0 {
					if outcome == 1 && branch.UnwitnessedTrue != "" {
						output = append(output, fmt.Sprintf("declared unwitnessed %s:%d in %s: %s", branch.File, branch.Line, branch.Function, branch.UnwitnessedTrue))
						continue
					}
					return nil, fmt.Errorf("uncovered if outcome=%t %s:%d in %s", outcome == 1, branch.File, branch.Line, branch.Function)
				}
				coveredOutcomes++
			}
		}
		output = append(output, fmt.Sprintf("%s: statements %d/%d = %.1f%%; if outcomes %d/%d = %.1f%%", function.Name, coveredStatements, statements, 100*float64(coveredStatements)/float64(statements), coveredOutcomes, outcomes, 100*float64(coveredOutcomes)/float64(outcomes)))
	}
	return output, nil
}

// Manifest rows saturate standard counters and if probes except the two declared
// Read syscall-error paths. Dropping the sole size refusal is a negative control.
func TestSharedFixtureCoverageGate(t *testing.T) {
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Clean(filepath.Join(current, "../.."))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || !filepath.IsAbs(root) {
		t.Fatal("coverage scratch is not an absolute physical path", err)
	}
	work := filepath.Join(root, "work")
	for _, name := range []string{"internal/identities", "tools/genjournal", "testdata/identities-v1"} {
		copyFixtureCoverageTree(t, filepath.Join(source, name), filepath.Join(work, name))
	}
	for _, name := range []string{"go.mod", "go.sum", "docs/identity-fixture-matrix.md"} {
		path := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(source, name))
		if err != nil || os.WriteFile(path, raw, 0644) != nil {
			t.Fatal("coverage input copy", name, err)
		}
	}
	functions, branches := prepareFixtureCoverage(t, work)
	run := func(name string) ([]byte, map[string][2]uint64) {
		t.Helper()
		profile, report := filepath.Join(root, name+".cover"), filepath.Join(root, name+".json")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		selection := "^(TestSharedFixtureCoverageRows|TestSharedCustodyFixtures)$"
		command := exec.CommandContext(ctx, "go", "test", "-p", "1", "-count=1", "-covermode=count", "-coverprofile="+profile, "-run", selection, "./internal/identities")
		command.Dir = work
		command.Env = append(os.Environ(), "SWARMA_SHARED_FIXTURE_COVERAGE_CHILD=1", "SWARMA_SHARED_FIXTURE_BRANCH_REPORT="+report)
		output, runErr := command.CombinedOutput()
		if command.ProcessState == nil {
			t.Fatal("coverage child did not start", runErr)
		}
		t.Logf("coverage child=%s pid=%d exit=%d selection=%s\n%s", name, command.ProcessState.Pid(), command.ProcessState.ExitCode(), selection, output)
		if runErr != nil {
			t.Fatal("shared-only coverage execution failed", runErr)
		}
		raw, err := os.ReadFile(profile)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		var hits map[string][2]uint64
		if err := json.Unmarshal(data, &hits); err != nil {
			t.Fatal(err)
		}
		return raw, hits
	}
	profile, hits := run("shared")
	output, err := verifyFixtureCoverage(profile, functions, branches, hits)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range output {
		t.Log(line)
	}
	t.Run("missing-refusal-control", func(t *testing.T) {
		manifest := fixtures(t)
		var rows []fixtureCase
		removed := false
		for _, row := range manifest.Cases {
			if row.Name == "oversized-document" {
				removed = true
			} else {
				rows = append(rows, row)
			}
		}
		if !removed {
			t.Fatal("coverage control plant was not applied")
		}
		manifest.Cases = rows
		raw, err := json.Marshal(manifest)
		if err != nil || os.WriteFile(filepath.Join(work, "testdata/identities-v1/cases.json"), raw, 0644) != nil {
			t.Fatal("coverage control manifest", err)
		}
		profile, hits := run("missing-size-refusal")
		_, err = verifyFixtureCoverage(profile, functions, branches, hits)
		if err == nil || !strings.Contains(err.Error(), "uncovered statement/refusal branch identities.go:") || !strings.Contains(err.Error(), "in Decode") {
			t.Fatal("missing shared refusal was not detected at its Decode line", err)
		}
		t.Log("expected refusal:", err)
	})
	t.Run("missing-accept-outcome-control", func(t *testing.T) {
		for _, branch := range branches {
			if branch.Function != "Document.Service" {
				continue
			}
			mutant := make(map[string][2]uint64, len(hits))
			for key, value := range hits {
				mutant[key] = value
			}
			counts := mutant[branch.ID]
			counts[0] = 0
			mutant[branch.ID] = counts
			_, err := verifyFixtureCoverage(profile, functions, branches, mutant)
			if err == nil || !strings.Contains(err.Error(), "uncovered if outcome=false "+branch.File+":"+strconv.Itoa(branch.Line)) {
				t.Fatal("missing if outcome was not detected", err)
			}
			t.Log("expected refusal:", err)
			return
		}
		t.Fatal("coverage if-outcome control was not applied")
	})
}
