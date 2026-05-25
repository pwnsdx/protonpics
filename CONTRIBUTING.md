# Contributing

Thanks for your interest in `protonpics`. This is an experimental, scope-limited project. Before you spend time on a change, please read this short note.

## Scope

This tool is intentionally narrow:

- one-way export of Proton Photos to local disk
- read-only with respect to Proton (no upload, no remote delete, no bidirectional sync)
- native Rust implementation, no Go bridge

Pull requests that expand the scope (full Proton Drive parity, write paths, sync, FIDO2, alternate cloud providers) may be declined or asked to live in a fork.

Pull requests that are in scope are very welcome:

- bug fixes
- robustness improvements (retry logic, error messages, recovery paths)
- coverage on existing untested branches
- documentation fixes
- safe performance work

## Before You Open a PR

Please make sure the following pass locally:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

If you change behavior, add or update tests. The project keeps a high coverage baseline (see [COVERAGE.md](COVERAGE.md)) and aims to keep new code at or above the same level.

## Style Notes

- Follow the existing module layout. `src/backend/proton.rs` is large but the layering inside it is intentional.
- Prefer small, focused commits with descriptive messages.
- Avoid adding dependencies for trivial reasons. New deps need a reason.
- Do not commit real account data, real session files, or real captured Proton responses.

## Reporting Issues

When reporting a bug, include:

- what command you ran
- what happened
- what you expected
- the relevant log output (with `--progress json` if useful), redacted of any sensitive fields
- the version of `protonpics` (or commit hash if from source)

Do not include passwords, TOTP codes, raw `session.json` content, or your tree cache. Those are sensitive.

## Security Issues

For anything that looks like a security issue, please do not open a public issue. See [SECURITY.md](SECURITY.md).
