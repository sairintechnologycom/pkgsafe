#!/usr/bin/env bash
set -uo pipefail

if [[ -z "${HOMEBREW_TAP_TOKEN:-}" ]]; then
  echo "::error title=GoReleaser preflight::HOMEBREW_TAP_TOKEN is not configured"
  exit 1
fi

log_file="${RUNNER_TEMP:-/tmp}/pkgsafe-goreleaser.log"

set +e
goreleaser release --clean 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

if [[ $status -ne 0 ]]; then
	# Keep the terminal failure within GitHub's annotation-size limit and strip
	# ANSI control sequences so the actual error is not truncated by styling.
	summary=$(tail -n 35 "$log_file" | sed $'s/\033\[[0-9;]*[[:alpha:]]//g')
  summary=${summary//'%'/'%25'}
  summary=${summary//$'\r'/'%0D'}
  summary=${summary//$'\n'/'%0A'}
  echo "::error title=GoReleaser failure::$summary"
fi

exit "$status"
