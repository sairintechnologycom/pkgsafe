#!/usr/bin/env bash
set -uo pipefail

log_file="${RUNNER_TEMP:-/tmp}/pkgsafe-race-tests.log"

set +e
go test -count=1 -race ./... 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

if [[ $status -ne 0 ]]; then
  echo "::group::Race test failure summary"
  tail -n 120 "$log_file"
  echo "::endgroup::"

  # Check-run annotations remain available through the public GitHub API even
  # when raw Actions logs require repository-admin authentication.
  while IFS= read -r line; do
    line=${line//'%'/'%25'}
    line=${line//$'\r'/'%0D'}
    line=${line//$'\n'/'%0A'}
    echo "::error title=Race test failure::$line"
  done < <(tail -n 40 "$log_file")
fi

exit "$status"
