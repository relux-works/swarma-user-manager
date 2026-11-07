#!/bin/bash
# Orchestrator only: every compiler, product and test runs in the offline namespace.
set -euo pipefail
umask 077
source_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
checks_dir=${1:?Supply an absolute, private output directory for retained check evidence}
case "$checks_dir" in /*) ;; *) printf '%s\n' 'Output directory must be absolute' >&2; exit 2 ;; esac
mkdir -m 700 -- "$checks_dir"
mkdir -m 700 -- "$checks_dir/home" "$checks_dir/tmp" "$checks_dir/cache" "$checks_dir/bin"
sandbox=(/usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
  --proc /proc --dev /dev --ro-bind "$source_root" /source --bind "$checks_dir" /private
  --setenv HOME /private/home --setenv TMPDIR /private/tmp --setenv XDG_CACHE_HOME /private/cache
  --setenv PATH /usr/bin:/bin --setenv LANG C.UTF-8 --setenv PYTHONDONTWRITEBYTECODE 1
  --setenv DEMO_TEST_EXECUTOR /private/bin/swarma-demo-executor --chdir /source)
# The recorder is fixed shell code and never loads a candidate-provided plugin.
run_check() {
  local name=$1
  shift
  local began ended code
  began=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  set +e
  /usr/bin/timeout --signal=KILL 120s "${sandbox[@]}" "$@" >"$checks_dir/$name.stdout" 2>"$checks_dir/$name.stderr"
  code=$?
  set -e
  ended=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf '%s\n' "$code" >"$checks_dir/$name.exit"
  printf 'started_at=%s\nfinished_at=%s\nexit=%s\nlimit_seconds=120\n' "$began" "$ended" "$code" >"$checks_dir/$name.receipt"
  cat -- "$checks_dir/$name.stdout" "$checks_dir/$name.stderr"
  return "$code"
}
run_check tools /usr/bin/python3 -I -S -c 'import platform,subprocess,sys; print(sys.version); print(platform.machine()); subprocess.run(["/usr/bin/gcc","--version"],check=True)'
run_check executor-build /usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror -Wformat=2 -Wconversion -o /private/bin/swarma-demo-executor /source/demo/executor.c
run_check fd-probe-build /usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror -Wformat=2 -Wconversion -o /private/bin/fd-probe /source/demo/tests/fd_probe.c
run_check tests /usr/bin/python3 -I -S -m unittest discover -s /source/demo/tests -v
