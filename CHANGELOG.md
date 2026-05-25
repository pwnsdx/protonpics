# Changelog

## 0.1.1 - 2026-05-25

Resilience release. The project was also renamed from `proton-photos-export` to `protonpics`.

### Changed

- **A single failed file no longer aborts the whole export.** Previously, if one file failed to download mid-batch, all in-flight workers were cancelled and the run exited with an error, losing partial progress on every concurrent download. Now each per-file failure is recorded and the batch keeps going on the remaining files. Successful files are committed to the SQLite state DB as they complete, so the next run skips them.
- **New exit code semantics for `export`:**
  - `0` — every file succeeded.
  - `1` — fatal error before or outside the download phase.
  - `2` — the run completed but at least one file failed. The summary line now ends with `failed=N`, followed by a list of the failed paths and their errors. Just rerun the same command to retry the failed files.
- **Renamed package, binary, lib crate, clap command name, and User-Agent / app-version strings to `protonpics`.** Local on-disk files (`session.json`, `proton-photos.sqlite`, `proton-tree-cache.json`) keep their existing names so existing setups are not disrupted.

### Added

- `LICENSE-MIT` and `LICENSE-APACHE` files (the package was already declared as MIT OR Apache-2.0 but the texts were missing)
- `CONTRIBUTING.md` and `SECURITY.md`
- A `Disclaimers` section in the README covering unofficial API use, lack of audit, and other caveats
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --all-targets` on Linux

### Fixed

- README claimed the default `--tree-cache` mode was `reuse-if-present`, but the code actually defaults to `refresh`. Documentation now matches the code.

## 0.1.0 - 2026-04-04

Initial public release.

### Added

- Native Rust Proton login, share listing, and photo export
- Interactive local account picker with encrypted `session.json` storage
- Proton human-verification and TOTP handling during login
- Resumable one-way export with SQLite state tracking
- `--dry-run` and `--delete-missing` export modes
- Human-friendly default CLI progress with:
  - remote tree scan status
  - active download progress bars
  - explicit up-to-date summaries
- Machine-readable progress mode via `--progress json`
- Manifest backend for local development and regression testing
- Offline mock-server coverage around native Proton flows

### Notes

- This tool is intentionally read-only
- It targets Proton Photos first, not general Drive parity
- FIDO2 login is not implemented
