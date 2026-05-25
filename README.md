# protonpics

Native Rust CLI that streams your Proton Photos to local disk. Read-only, resumable, SQLite-backed.

## The Problem

Proton Photos has no built-in bulk export. Selecting tens of thousands of photos in the web app and clicking download does not work in practice — the browser tab dies before the archive starts streaming. The Photos share is also separate from the normal Drive file view, so common third-party Proton Drive tools tend not to expose it.

`protonpics` is the pragmatic answer to that:

- log in to Proton
- access the Proton Photos share (`PhotosRoot` by default)
- stream files to a local directory in parallel
- keep a local SQLite state database so repeated runs skip unchanged files
- resume cleanly after `Ctrl-C`, network errors, or rate limits

It is not a general Proton Drive client and it is not a bidirectional sync tool.

## Disclaimers

Read this section before using the tool.

- **Independent project.** This is an unofficial, third-party tool. It is not affiliated with, endorsed by, or supported by Proton AG.
- **Unofficial API use.** The tool talks to Proton's web API endpoints by reimplementing the protocol used by Proton's own clients. Those endpoints are not a documented public API. Proton may change them at any time and break this tool, and use of those endpoints may be subject to Proton's Terms of Service. You are responsible for reviewing those terms before running this tool against your account.
- **Experimental status.** This is a 0.x release. Behavior, on-disk formats, the local SQLite schema, and the encrypted `session.json` envelope may change between versions in incompatible ways.
- **No security audit.** The login flow, SRP implementation, session encryption, and tree cache encryption have not been independently audited. Treat this tool accordingly when deciding what to run it against.
- **Read-only by design, but verify.** The tool is one-way (Proton to local disk) and is built to never write back to Proton. As with any backup tool, verify the exported files before relying on them as a backup.
- **`--delete-missing` is destructive.** When enabled, it removes local files that no longer exist remotely. Test with `--dry-run` first.
- **No warranty.** Provided as-is under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## How It Works

- **Native Rust** end-to-end. No Go bridge, no helper process, no headless browser.
- **SRP login** with TOTP and human-verification (CAPTCHA) flows handled locally.
- **Encrypted `session.json`** so the raw account password is never stored.
- **Parallel tree scan** with a bounded worker pool.
- **Parallel block downloads** with prefetching for large files.
- **SQLite state** so reruns skip files whose remote revision has not changed.
- **Atomic writes** via temp file plus rename.

## Status

Current scope:

- native Rust login
- native Rust share listing
- native Rust Proton Photos export
- encrypted local session storage
- automatic token refresh
- local CAPTCHA / human-verification handling during login
- local SQLite sync state
- dry-run support
- optional local delete of files that disappeared remotely

Current non-goals:

- upload
- remote delete
- bidirectional sync
- FIDO2 login
- full Proton Drive parity

## Installation

This project is source-installable today.

Build a release binary:

```bash
cargo build --release
```

Then run:

```bash
./target/release/protonpics --help
```

Or install into Cargo's bin directory:

```bash
cargo install --path .
```

Then run:

```bash
protonpics --help
```

## Quick Start

Choose a working directory first. The default local account store is based on your current working directory, not the binary location.

Example:

```bash
mkdir -p ~/Backups/proton-photos
cd ~/Backups/proton-photos
```

Login interactively:

```bash
protonpics login
```

List shares:

```bash
protonpics shares
```

Export photos:

```bash
protonpics export --to ./photos proton
```

By default, Proton exports rescan the remote tree on every run and refresh the local encrypted tree cache. This is the safe default: new files added on Proton since the previous run will always be picked up.

Force a fresh tree scan explicitly (this is the default, shown for clarity):

```bash
protonpics export --to ./photos proton --tree-cache refresh
```

Reuse the local tree cache without rescanning Proton, when the cache is present and valid. This is faster on reruns but will not pick up new remote files until the next refresh:

```bash
protonpics export --to ./photos proton --tree-cache reuse-if-present
```

Disable tree-cache reads and writes entirely:

```bash
protonpics export --to ./photos proton --tree-cache off
```

Tune file download parallelism for better throughput:

```bash
protonpics export --to ./photos --download-concurrency 4 proton
```

Tune remote-tree scan parallelism for large libraries:

```bash
protonpics export --to ./photos proton --scan-concurrency 8
```

Interactive runs show human-friendly progress by default.

Force human progress explicitly:

```bash
protonpics export --progress --to ./photos proton
```

Machine-readable JSON progress:

```bash
protonpics export --progress json --to ./photos proton
```

Disable progress output:

```bash
protonpics export --progress off --to ./photos proton
```

## Important CLI Syntax

Under `export`, export-level flags must come before the source subcommand.

Correct:

```bash
protonpics export --to ./photos proton
```

Incorrect:

```bash
protonpics export proton --to ./photos
```

If your path contains spaces, quote it normally. Do not escape spaces inside the quotes.

Correct:

```bash
protonpics export --to "/Volumes/Macintosh Files/Backups/2026 Backup/Pictures" proton
```

Incorrect:

```bash
protonpics export --to "/Volumes/Macintosh\ Files/Backups/2026 Backup/Pictures" proton
```

## Account And Session Storage

By default, `login` stores one encrypted session file per account under the current working directory:

```text
./<email>/session.json
```

For example:

```text
./alice@proton.me/session.json
```

When exporting from Proton, the default state database lives next to that session file:

```text
./<email>/proton-photos.sqlite
```

So a typical working directory may end up like this:

```text
./alice@proton.me/session.json
./alice@proton.me/proton-photos.sqlite
./photos/...
```

If you do not want that layout, pass `--credentials` and optionally `--state-db` explicitly.

## Security Model

Interactive `login` does not store your Proton password in plain text.

The saved `session.json` contains an encrypted envelope that wraps reusable Proton auth material such as:

- UID
- access token
- refresh token
- salted key pass used to unlock Proton keys locally

The default session file is encrypted with the Proton account password you entered during login.

Practical implications:

- the raw account password is not stored
- TOTP codes are not stored
- `session.json` is still sensitive and should be protected
- `--password` on the command line is supported for automation, but interactive login is safer for normal use because it avoids shell history and process-argument exposure

## Login Flow

Interactive login:

```bash
protonpics login
```

If Proton requires human verification, the CLI opens a local browser page and waits for completion.

If your Proton account uses:

- TOTP 2FA: the CLI prompts for the code
- separate mailbox password: the CLI prompts for that too

FIDO2 login is not implemented.

You can also drive login non-interactively:

```bash
protonpics login \
  --credentials ./custom/session.json \
  --email "you@example.com" \
  --password "..."
```

## Common Commands

Show top-level help:

```bash
protonpics --help
```

Login:

```bash
protonpics login
```

List shares:

```bash
protonpics shares
```

Export Proton Photos:

```bash
protonpics export --to ./photos proton
```

Export a different share by name:

```bash
protonpics export --to ./out proton --share-name "Some Other Share"
```

Export a specific share by ID:

```bash
protonpics export --to ./out proton --share-id "share-id-here"
```

Dry-run:

```bash
protonpics export --dry-run --to ./photos proton
```

Delete local files that no longer exist remotely:

```bash
protonpics export --delete-missing --to ./photos proton
```

Inspect the state database:

```bash
protonpics state --state-db ./alice@proton.me/proton-photos.sqlite
```

## Share Selection

The default Proton export target is:

```text
PhotosRoot
```

That is the share used by Proton's photo backup flow.

If you run `shares` or `export` without `--credentials` and saved accounts exist in the current working directory, the CLI shows an interactive account picker.

If no saved account exists, the CLI can prompt to add one.

## Progress Output

Interactive runs use a human-friendly spinner and download bar by default.

Progress modes:

- default / `--progress`: human-friendly output
- `--progress json`: structured JSON lines to `stderr`
- `--progress off`: disable progress output

Human-friendly mode shows:

- a scan spinner while the remote tree is loading
- live folder/file counts while the tree scan is still in progress
- a persistent scan summary once listing is complete
- a byte-level bar for the active download in single-download mode
- batch download status when multiple files are downloading concurrently
- an explicit up-to-date message when nothing needs downloading

For large libraries, tree loading is usually the main bottleneck. The Proton backend now scans folders and albums in parallel with a bounded worker pool. The default is `4` concurrent scans, and you can tune it with `--scan-concurrency` or `PROTON_SCAN_CONCURRENCY`.

File downloads are also parallelized. The default is `4` concurrent downloads, and you can tune it with `--download-concurrency`. Start with `4`, then try `8` if your connection and Proton account tolerate it well.

Large files also benefit from block prefetching inside each active download, so video exports should no longer wait for every Proton block strictly one-by-one.

Example:

```json
{"type":"progress","phase":"tree_load","status":"start","backend":"proton","share_name":"PhotosRoot","share_id":null}
{"type":"progress","phase":"tree_load","status":"complete","backend":"proton","share_id":"...","root_id":"...","folders":12,"files":438}
{"type":"progress","phase":"download","status":"start","backend":"proton","path":"2026/photo.jpg","remote_id":"...","size":12345,"index":1,"total":438}
{"type":"progress","phase":"download","status":"complete","backend":"proton","path":"2026/photo.jpg","remote_id":"...","bytes":12345,"index":1,"total":438}
```

This is useful if you want to wrap the tool in another script or parse status programmatically.

## Environment Variables

The CLI supports these environment variables:

- `PROTON_CREDENTIALS_FILE`
- `PROTON_EMAIL`
- `PROTON_PASSWORD`
- `PROTON_MFA`
- `PROTON_ACCOUNT_PASSWORD`
- `PROTON_APP_VERSION`
- `PROTON_USER_AGENT`
- `PROTON_SCAN_CONCURRENCY`

These are mainly useful for automation. For normal interactive usage, you usually do not need them.

## Export Semantics

This tool is intentionally conservative.

- It only downloads from Proton to local disk.
- It never writes back to Proton.
- `--delete-missing` only deletes local files that are no longer present remotely.
- Downloads are written atomically via temp file + rename.
- The SQLite state DB is used to skip unchanged files when possible.

## Manifest Backend

The `manifest` source exists for local testing and development of the export engine without real Proton credentials.

Example:

```bash
protonpics export \
  --to ./out \
  --state-db ./out/test.sqlite \
  manifest \
  --manifest ./photos.json
```

Example manifest:

```json
{
  "root_id": "photos-root",
  "children": [
    {
      "kind": "folder",
      "id": "year-2026",
      "name": "2026",
      "children": [
        {
          "kind": "file",
          "id": "photo-1",
          "name": "beach.jpg",
          "revision_id": "rev-1",
          "size": 1234,
          "modified_at_ns": 1767225600000000000,
          "source_path": "fixtures/beach.jpg"
        }
      ]
    }
  ]
}
```

`source_path` may be absolute or relative to the manifest file.

## Limitations

- experimental project
- Proton APIs may change
- FIDO2 login is not implemented
- not packaged for Homebrew or crates.io yet
- focused on Photos export, not full Drive support

## Development

Run tests:

```bash
cargo test
```

Run linting:

```bash
cargo clippy --all-targets -- -D warnings
```

Run coverage:

```bash
cargo llvm-cov --workspace --all-features --summary-only
```

## License

Dual licensed under:

- MIT
- Apache-2.0
