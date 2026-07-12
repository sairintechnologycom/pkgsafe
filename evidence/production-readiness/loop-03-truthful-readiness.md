# Loop 03 - Truthful Readiness Metrics and Benchmark Semantics

Date: 2026-07-12  
Status: accepted

## Feature result

Loop 03 closes PSR-006 by making readiness accounting explicit and
non-overlapping.

Key changes in `internal/validation/benchmark.go`:

- `PackagesConfigured`, `PackagesAttempted`, `PackagesExecuted`, and
  `PackagesSkipped` are tracked as disjoint counters.
- `PackagesPassed` is only incremented for executed results.
- `CandidateStatusEligible` now requires executed samples, minimum coverage,
  and zero executed failures.
- Connected online summaries now distinguish `no_executed_samples` from a real
  `fail` state.
- Skipped rows remain skipped; they are not re-labeled as passes.
- Production-readiness gating now requires real repository evidence to be
  observed, trustworthy timing, and the configured threshold.

The readiness report now exposes explicit fields for:

- benchmark candidate eligibility
- configured / executed / skipped counts
- coverage ratio
- real repository validation count
- timing trustworthiness

## Validation evidence

Focused validation of the benchmark semantics:

```text
go test ./internal/validation
PASS
```

Full repository validation after the fix:

```text
env GOCACHE=/tmp/pkgsafe-gocache go test ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go test -race ./...
PASS

env GOCACHE=/tmp/pkgsafe-gocache go vet ./...
PASS
```

The full suite initially failed on
`TestOnlineSummaryDistinguishesNoExecutedSamples` because connected runs with
zero executed packages were still being reported as `no_network`. That status
was corrected to `no_executed_samples`, and the suite passed on rerun.

## Current observed behavior

Representative accounting now behaves as follows:

- offline cache misses are counted as skipped, not passed;
- 0 executed / 25 skipped yields `BENCHMARK_EVIDENCE_INELIGIBLE`;
- 1 executed / 24 skipped yields `BENCHMARK_EVIDENCE_INELIGIBLE`;
- 20 executed / 5 skipped reaches candidate eligibility;
- connected runs with no executed samples are reported as
  `no_executed_samples`.

The production-readiness gate now fails when real repository evidence is below
threshold or when timing is not trustworthy, rather than inferring readiness
from fixture pass counts alone.

## Commands and observed results

```text
go test ./internal/validation
PASS

go test ./...
PASS

go test -race ./...
PASS

go vet ./...
PASS
```

## Completion gate

| Gate | State |
| --- | --- |
| PSR-006 | CLOSED |
| skips counted as pass | 0 |
| readiness labels derived from executed evidence only | PASS |
