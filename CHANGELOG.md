# Changelog

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
