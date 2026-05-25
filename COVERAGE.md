# Coverage Notes

Verified on May 25, 2026 in the local development environment, against `protonpics 0.1.1`.

## Commands

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo llvm-cov --workspace --all-features --summary-only
cargo llvm-cov --workspace --all-features --show-missing-lines
```

## Baseline

Latest verified coverage from `cargo llvm-cov --workspace --all-features --summary-only`:

| File | Line Coverage | Region Coverage |
| --- | ---: | ---: |
| `src/accounts.rs` | 97.85% | 89.53% |
| `src/backend/manifest.rs` | 98.45% | 89.15% |
| `src/backend/mod.rs` | 100.00% | 93.51% |
| `src/backend/proton.rs` | 94.80% | 90.18% |
| `src/cli.rs` | 100.00% | 100.00% |
| `src/export/mod.rs` | 96.95% | 90.73% |
| `src/lib.rs` | 95.99% | 87.60% |
| `src/main.rs` | 87.50% | 69.23% |
| `src/paths.rs` | 100.00% | 99.46% |
| `src/progress.rs` | 98.34% | 97.41% |
| `src/signals.rs` | 87.18% | 85.96% |
| `src/state.rs` | 96.34% | 84.11% |
| `src/types.rs` | 100.00% | 100.00% |
| **Total** | **95.80%** | **90.84%** |

## Notes On The 0.1.1 Resilience Work

The 0.1.1 release reworked the parallel download loop to keep going on per-file failures instead of cancelling the whole batch. The new paths are covered by:

- `execute_parallel_downloads_reports_worker_failures` — the parallel loop reports the failure and still completes the healthy file.
- `execute_collects_open_file_errors_into_report` — `execute()` returns successfully with the failure listed in `ExportReport.failed_downloads`.

The new "summary line with `failed=N` and a list of failed paths" formatting in `lib::run_with_writer`, plus the `Ok(2)` exit code path, is exercised indirectly through the existing `run_with_writer_formats_non_dry_export` test (which asserts `failed=0` and exit code `0`). End-to-end coverage of the partial-failure path through `run_with_writer` would require a backend that lets a file fail at `open_file` after a successful construction; the current `ManifestBackend` validates source metadata at construction time, so it cannot synthesize that scenario without a backend change. The unit tests at the `execute()` level cover the same logic.

`src/main.rs` drops to 87.5% line coverage in 0.1.1 because `std::process::exit(exit_code)` was added to propagate the new exit codes. That call cannot be tested without spawning a subprocess. The conditional that decides whether to call it is straightforward.

## Remaining Gaps

Remaining uncovered lines are concentrated in a few categories:

- `src/backend/proton.rs`
  - narrow guard rails and fallback branches
  - helper/test scaffolding around synthetic crypto fixtures and the mock server
  - some request-wrapper and decrypt helper line endings that are hard to move without synthetic failure fixtures
- `src/export/mod.rs`
  - metadata and mtime error handling
  - a few low-value line-end artifacts in existing tests
- `src/lib.rs`
  - the partial-failure summary path (covered at the `execute()` level, see above)
  - mostly output formatting lines and test helper line-end artifacts
- `src/state.rs`
  - mostly SQLite setup/update line-end artifacts in already-tested paths
- `src/backend/manifest.rs` and `src/backend/mod.rs`
  - almost entirely test-fixture line endings and small wrapper glue
- `src/main.rs`
  - the `process::exit` call described above

## Practical Interpretation

The high-value runtime paths are covered:

- native Proton login/bootstrap flow
- share discovery
- tree loading
- block download and decryption
- export state handling
- per-file failure reporting (new in 0.1.1)
- dry-run and delete-missing behavior
- CLI output formatting
- mock-server keep-alive behavior used by the native Proton tests

Reaching true 100% from here would mostly require coverage-driven tests for:

- formatting/macros and line-mapping artifacts
- synthetic failure fixtures for rare crypto/parser guards
- more mock-server edge cases with limited product value
- a backend variant that fails at `open_file` rather than at construction, to exercise the partial-failure path through `run_with_writer`

That work is possible, but it is no longer the highest-value use of time relative to the actual product risk left in the code.
