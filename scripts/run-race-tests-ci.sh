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
	# when raw Actions logs require repository-admin authentication. GitHub only
	# retains a small number of command annotations per step, so emit one
	# multiline annotation containing the actual failure/race context.
	summary=$(grep -n -E -B 5 -A 30 'WARNING: DATA RACE|--- FAIL:|^FAIL([[:space:]]|$)|race detected|panic:|fatal error:' "$log_file" | tail -n 100 || true)
	if [[ -z "$summary" ]]; then
		summary=$(tail -n 100 "$log_file")
	fi
	summary=${summary//'%'/'%25'}
	summary=${summary//$'\r'/'%0D'}
	summary=${summary//$'\n'/'%0A'}
	echo "::error title=Race test failure::$summary"
fi

exit "$status"
