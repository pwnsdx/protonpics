# Security Policy

## Scope

`protonpics` handles sensitive material:

- Proton account passwords (in memory, during interactive login)
- the salted key pass derived from your Proton password
- Proton access and refresh tokens, persisted in an encrypted `session.json`
- the local encrypted tree cache (`proton-tree-cache.json`)
- the local SQLite state database

Anything that could expose, leak, weaken, or misuse this material is in scope for a security report. So is anything that lets an unprivileged process on the same machine read decrypted secrets, anything that leaks credentials over the network outside of Proton's expected endpoints, and anything that breaks the read-only guarantee against Proton.

## Reporting

Please report security issues privately, not through public GitHub issues.

Send your report to **pwnsdx@protonmail.ch**.

This is a Proton Mail address, so most modern mail clients can fetch the recipient's PGP key automatically (via WKD) and encrypt the report end-to-end. If your client supports it, please send the report encrypted.

## What to Include

When you do reach a maintainer, please include:

- a clear description of the issue
- a minimal reproduction (commands, configuration, redacted logs)
- the version of `protonpics` you tested
- your assessment of impact

Do not include real Proton credentials, real tokens, or real `session.json` content in any report. If a reproduction needs sensitive data, describe it abstractly and say so.

## What Is Out of Scope

- Bugs that only affect builds on unsupported toolchains
- Issues caused by patched local copies of Proton's API endpoints
- Findings that require an attacker who already has full read-write access to the user's home directory
- General concerns about Proton's own service or infrastructure (please report those to Proton)
- The fact that this tool is not security-audited (it isn't, and the README says so)

## No Audit, No Warranty

This project has not been independently audited. It is offered as-is under MIT or Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
