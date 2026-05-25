# Release Notes

## protonpics 0.1.0

`protonpics` is a native Rust CLI for exporting Proton Photos to local disk.

This release focuses on one job:

- log in to Proton
- find the Photos share
- download files locally
- resume cleanly on later runs

### Highlights

- Native Rust Proton login and export path
- Interactive account selection with encrypted local session storage
- Human-verification and TOTP support during login
- Human-friendly default progress output in the terminal
- JSON progress mode for wrappers and automation
- SQLite state tracking for resumable exports

### Example

```bash
protonpics export --to "/path/to/Pictures" proton
```

### Progress Modes

- default: human-friendly progress for terminal runs
- `--progress json`: structured progress events
- `--progress off`: disable progress output

### Scope

Included:

- one-way photo export
- repeated sync-style reruns
- optional local deletion of missing remote files

Not included:

- uploads
- remote deletes
- bidirectional sync
- full Proton Drive parity
- FIDO2 login

### Operational Notes

- By default, account data is stored under the current working directory
- Proton sessions are stored in encrypted `session.json` files
- Repeated runs use a local SQLite database to skip unchanged files
