# Changelog

## 0.1.3 - 2026-05-26

Fix the metadata-restoration pipeline shipped in 0.1.2.

### Fixed

- **XAttr decryption now walks into compressed payloads.** Proton clients ship the per-file `XAttr` blob wrapped in a Compressed Data Packet (zlib), then encrypted. The 0.1.2 decryption helper called `Message::decrypt` and read the result directly, which returned raw deflate bytes that failed the `String::from_utf8` check inside `decrypt_text`. Every file silently fell through to the upload-time fallback, leaving `original_modified_at_ns` and `capture_time_ns` `NULL` in the state DB and the on-disk timestamps unchanged. The fix is a single `.decompress()` call in `SecretKeyRing::decrypt_armored_message`, which is a no-op when the inner packet is already a Literal Data Packet.

### How To Recover

If you ran 0.1.2 and your timestamps are still wrong:

```bash
# 1. Re-run export. Existing files are skipped, but the state DB is now
#    populated with the decrypted timestamps for every file.
protonpics export --to ./photos proton

# 2. Apply those timestamps in place. No re-download.
protonpics repair-metadata --to ./photos
```

### Tests

- New regression test `decrypt_armored_message_walks_into_compressed_payload` constructs a PGP message wrapped in `CompressionAlgorithm::ZLIB`, encrypts it, and asserts that `decrypt_armored_message` returns the inner plaintext. This locks the bug down so it cannot regress silently again.

## 0.1.2 - 2026-05-26

Restores original photo timestamps. Files exported from Proton Photos used to land on disk with the upload timestamp, not the timestamp the user actually had locally before uploading. This release fixes that.

### Changed

- **`export` now restores the original modification time on every downloaded file.** The original mtime is read from the encrypted XAttr blob attached to each Proton link (`Common.ModificationTime`), decrypted with the file's own node key, and applied at write time. When the XAttr is missing or unreadable for any reason (e.g. files uploaded by very old clients), the upload time is used as a fallback so the export never regresses to a worse state.
- **macOS only: birthtime is also restored.** The OS-level "creation time" is set via `setattrlist` from `Camera.CaptureTime` when present, falling back to `Common.ModificationTime` and finally the upload time. Linux and Windows have no portable equivalent, so the call is a no-op there.
- **State DB schema bumped to v2.** Two new nullable columns track the restored timestamps so reruns can stay fast even when the XAttr decode fails on a particular file. Existing v1 databases are migrated forward in place; older versions of the tool will refuse to open a v2 DB on purpose.
- **Tree cache version bumped to v2.** Caches written by 0.1.1 or earlier are silently rejected and rebuilt on the first run.

### Added

- New `repair-metadata` subcommand. Use it after upgrading: run `protonpics export ...` once to backfill the new state-DB columns, then `protonpics repair-metadata --to ./photos` to retroactively fix every existing local file's mtime and birthtime without re-downloading. Supports `--dry-run`.

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
