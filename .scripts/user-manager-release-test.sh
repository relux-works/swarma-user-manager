#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
fail() { printf "user manager release controls: %s\n" "$1" >&2; exit 1; }
[[ $# == 2 && $1 == /* && $2 == /* ]] || fail absolute-suite-fixture-and-new-scratch-required
source_root=$(cd "$(dirname "$0")/.." && pwd -P)
fixture=$(cd "$1" && pwd -P)
[[ -d $fixture/build-source/.git ]] || fail completed-release-suite-fixture-required
go_bin=$(command -v "${GO:-go}")
mkdir "$2"
scratch=$(cd "$2" && pwd -P)
mkdir -p "$scratch"/{home,config,cache,tmp,go-build,go-mod,go-path,policy/.scripts,policy/.github/release}
export HOME="$scratch/home" USERPROFILE="$scratch/home"
export XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache"
export GOCACHE="$scratch/go-build" GOMODCACHE="$scratch/go-mod" GOPATH="$scratch/go-path"
export TMPDIR="$scratch/tmp" GOTMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp"
export GO="$go_bin" GOFLAGS=-p=2 GOENV=off GOWORK=off GOTOOLCHAIN=local GOTELEMETRY=off
unset GOTELEMETRYDIR
cp "$source_root"/.scripts/release-* "$scratch/policy/.scripts/"
printf "example_linux_amd64\nexample_linux_arm64\n" > "$scratch/expected"
cp "$scratch/expected" "$scratch/policy/.github/release/expected-artifacts"
builder="$scratch/policy/.scripts/release-build.sh"
expect_refusal() {
  local name=$1 reason=$2 status
  shift 2
  if "$@" > "$scratch/$name.log" 2>&1; then
    fail "$name: unexpected acceptance"
  else
    status=$?
    [[ $status == 1 ]] || fail "$name: unexpected exit $status"
    grep -F -- "$reason" "$scratch/$name.log" > /dev/null || fail "$name: wrong refusal"
    printf "PASS %s (expected refusal exit %s: %s)\n" "$name" "$status" "$reason"
  fi
}

# The real builder accepts the fixture, then rejects missing and extra binaries
# against main-owned policy; these are the retained repository-specific names.
"$builder" "$scratch/valid" "$fixture/build-source" > "$scratch/fixture_build.log" 2>&1
printf "PASS fixture_build (exit 0)\n"
printf "example_linux_amd64\nexample_linux_arm64\nmissing-tool_linux_amd64\n" > "$scratch/policy/.github/release/expected-artifacts"
expect_refusal missing_artifact unexpected-artifact-set "$builder" "$scratch/set-missing" "$fixture/build-source"
printf "example_linux_amd64\n" > "$scratch/policy/.github/release/expected-artifacts"
expect_refusal extra_artifact unexpected-artifact-set "$builder" "$scratch/set-extra" "$fixture/build-source"

# Missing policy must fail on that exact file before creating build output.
rm "$scratch/policy/.github/release/expected-artifacts"
expect_refusal missing_expected_list "No such file or directory" "$builder" "$scratch/set-nolist" "$fixture/build-source"
grep -F -- "/.github/release/expected-artifacts" "$scratch/missing_expected_list.log" > /dev/null || fail missing_expected_list-wrong-path
[[ ! -e $scratch/set-nolist ]] || fail missing_expected_list-partial-output
cp "$scratch/expected" "$scratch/policy/.github/release/expected-artifacts"
"$builder" "$scratch/restored" "$fixture/build-source" > "$scratch/restored_fixture_build.log" 2>&1
cmp "$scratch/valid/SHA256SUMS" "$scratch/restored/SHA256SUMS"
printf "PASS restored_fixture_build (exit 0)\n"
printf "Repository-specific release controls passed; scratch evidence retained at %s\n" "$scratch"
