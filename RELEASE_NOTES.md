# Release Notes

These notes cover the latest release. See [`CHANGELOG.md`](CHANGELOG.md) for the full history.

## protonpics 0.1.1 — 2026-05-25

A resilience release. The project was also renamed from `proton-photos-export` to `protonpics`.

### Highlights

- **Per-file failures no longer cancel the whole batch.** A single bad file used to take every concurrent download with it. Now the batch keeps going on the rest of the files, the failures are listed at the end, and a rerun retries them.
- **New exit codes for `export`:**
  - `0` — every file succeeded
  - `2` — the run completed but some files failed (rerun to retry)
  - `1` — fatal error before or outside the download phase
- **Renamed** package, binary, lib crate, clap command, and User-Agent / app-version strings to `protonpics`. Local on-disk files (`session.json`, `proton-photos.sqlite`, `proton-tree-cache.json`) keep their existing names so existing setups are not disrupted.

### Example

```bash
protonpics export --to "/path/to/Pictures" --download-concurrency 8 proton --scan-concurrency 8
```

After the run, the summary line ends with `failed=N`. If `N > 0`, the failed paths are listed and the process exits with code `2`. The successful files are committed to the SQLite state DB as they complete, so a rerun naturally skips them and only retries the failures.

### Also In This Release

- `LICENSE-MIT` and `LICENSE-APACHE` files
- `CONTRIBUTING.md` and `SECURITY.md`
- A `Disclaimers` section in the README
- GitHub Actions CI: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --all-targets` on Linux
- README fix: the documented default for `--tree-cache` was wrong, the code defaults to `refresh` (full rescan on every run)

### Scope

This release does not change the project's intentional limits:

- one-way photo export only
- read-only with respect to Proton
- no upload, no remote delete, no bidirectional sync, no full Proton Drive parity, no FIDO2 login

### Operational Notes

- Account data is stored under the current working directory by default
- Proton sessions are stored in encrypted `session.json` files
- Repeated runs use a local SQLite database to skip unchanged files
