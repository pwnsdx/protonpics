# Release Notes

These notes cover the latest release. See [`CHANGELOG.md`](CHANGELOG.md) for the full history.

## protonpics 0.1.2 — 2026-05-26

A correctness release: photos now land on disk with the right timestamp.

### The Problem

Before 0.1.2, files exported from Proton Photos got the **upload time** as their on-disk modification time, not the time the user actually had on the file before uploading. Sorting your library by date in Finder, importing into Photos.app, or any tool that relies on filesystem timestamps gave the wrong answer.

The original mtime was never lost. Proton already stores it (encrypted) in each link's `XAttr` blob, in the `Common.ModificationTime` field. The web app and the official mobile clients use it to display the right date when you scroll. Earlier versions of `protonpics` simply did not decrypt that blob.

### The Fix

- **`export` now decrypts the XAttr blob** for every file at scan time and applies the original mtime at write time. No additional API roundtrips: the encrypted blob is already returned with the link metadata. Decryption uses the file's own node key, which `protonpics` was already deriving for the block download path.
- **On macOS, the file birthtime is also restored** via `setattrlist`. We prefer `Camera.CaptureTime` (when the file is a photo or a video) and fall back to `Common.ModificationTime`, then the upload time. Linux and Windows have no portable equivalent, so on those platforms the birthtime call is a no-op.
- **Failures are graceful.** A file whose XAttr is missing, unreadable, or malformed simply falls back to the upload time as before. The scan never aborts because of metadata decoding.

### `repair-metadata`: Fix Files You Already Downloaded

If you already have thousands of files exported with the old (wrong) timestamps, you do not need to re-download them. The new `repair-metadata` subcommand walks the SQLite state DB and rewrites the on-disk mtime and birthtime in place.

The recommended workflow after upgrading:

```bash
# 1. Re-run export. It is incremental, so existing files are skipped, but
#    the state DB is updated with the original timestamps decoded from XAttr.
protonpics export --to ./photos proton

# 2. Apply those timestamps to the existing files.
protonpics repair-metadata --to ./photos
```

`--dry-run` is supported.

### Behind The Scenes

- New `original_modified_at_ns` and `capture_time_ns` columns on the SQLite state DB. The DB schema is bumped from v1 to v2 with an in-place migration.
- New `RepairOptions`, `RepairReport`, and `RepairFailure` public types in `protonpics::export` for callers that want to drive `repair-metadata` from a wrapper.
- Tree cache version bumped to v2; the previous cache is rebuilt automatically on the next run.

### Scope (unchanged)

- one-way photo export only
- read-only with respect to Proton
- no upload, no remote delete, no bidirectional sync, no full Proton Drive parity, no FIDO2 login

### Operational Notes

- Account data is stored under the current working directory by default
- Proton sessions are stored in encrypted `session.json` files
- Repeated runs use a local SQLite database to skip unchanged files

## protonpics 0.1.1 — 2026-05-25

A resilience release. The project was also renamed from `proton-photos-export` to `protonpics`.

### Highlights

- **Per-file failures no longer cancel the whole batch.** A single bad file used to take every concurrent download with it. Now the batch keeps going on the rest of the files, the failures are listed at the end, and a rerun retries them.
- **New exit codes for `export`:**
  - `0` — every file succeeded
  - `2` — the run completed but some files failed (rerun to retry)
  - `1` — fatal error before or outside the download phase
- **Renamed** package, binary, lib crate, clap command, and User-Agent / app-version strings to `protonpics`. Local on-disk files (`session.json`, `proton-photos.sqlite`, `proton-tree-cache.json`) keep their existing names so existing setups are not disrupted.
