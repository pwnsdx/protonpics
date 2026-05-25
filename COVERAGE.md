# Coverage Notes

Verified on May 25, 2026 in the local development environment.

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
| `src/export/mod.rs` | 97.01% | 90.63% |
| `src/lib.rs` | 98.95% | 90.36% |
| `src/main.rs` | 100.00% | 83.33% |
| `src/paths.rs` | 100.00% | 99.46% |
| `src/progress.rs` | 98.34% | 97.41% |
| `src/signals.rs` | 87.18% | 85.96% |
| `src/state.rs` | 96.34% | 84.11% |
| `src/types.rs` | 100.00% | 100.00% |
| **Total** | **95.91%** | **90.95%** |

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
  - mostly output formatting lines and test helper line-end artifacts
- `src/state.rs`
  - mostly SQLite setup/update line-end artifacts in already-tested paths
- `src/backend/manifest.rs` and `src/backend/mod.rs`
  - almost entirely test-fixture line endings and small wrapper glue

The latest `--show-missing-lines` report points to these specific residual files:

- `src/backend/proton.rs`
- `src/export/mod.rs`
- `src/lib.rs`
- `src/state.rs`
- `src/backend/manifest.rs`
- `src/backend/mod.rs`
- `src/progress.rs`
- `src/cli.rs`

## Practical Interpretation

The high-value runtime paths are covered:

- native Proton login/bootstrap flow
- share discovery
- tree loading
- block download and decryption
- export state handling
- dry-run and delete-missing behavior
- CLI output formatting
- mock-server keep-alive behavior used by the native Proton tests

Reaching true 100% from here would mostly require coverage-driven tests for:

- formatting/macros and line-mapping artifacts
- synthetic failure fixtures for rare crypto/parser guards
- more mock-server edge cases with limited product value

That work is possible, but it is no longer the highest-value use of time relative to the actual product risk left in the code.
