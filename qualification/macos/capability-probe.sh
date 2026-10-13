#!/bin/bash
# No probe code, including cleanup, is entered until the hosted-runner guard passes.
set -euo pipefail
if [[ ${GITHUB_ACTIONS:-} != true || ${RUNNER_ENVIRONMENT:-} != github-hosted || ${RUNNER_OS:-} != macOS ]]; then
  echo 'Refusing: qualification requires a GitHub-hosted macOS runner.' >&2
  exit 64
fi
case ${PROBE_RUNNER_LABEL:-} in macos-14|macos-15) ;; *) exit 64 ;; esac
major=$(/usr/bin/sw_vers -productVersion)
if [[ ${major%%.*} != ${PROBE_RUNNER_LABEL#macos-} || $EUID != 0 ]]; then
  echo 'Refusing: OS label mismatch or missing root privilege.' >&2
  exit 64
fi
exec "${PROBE_PYTHON:?}" "$(dirname "$0")/probe.py" "${1:?output directory required}"
