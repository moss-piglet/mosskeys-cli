# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **do not open a public issue**.

Please report it privately via one of:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/moss-piglet/mosskeys-cli/security/advisories/new)
- **Email**: security@mosspiglet.dev

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Scope

This policy covers the `mosskeys-cli` workspace:

- `mosskeys-core`: the write-API client, config/credential handling, and local BYOK checkpoint signing
- `mosskeys-cli`: the `mosskeys` binary (clap commands, output)

The cryptographic core lives in [`metamorphic-crypto`](https://github.com/moss-piglet/metamorphic-crypto)
and [`metamorphic-log`](https://github.com/moss-piglet/metamorphic-log); report
issues in the primitives there.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Security Design

- Zero-knowledge by construction: the CLI transmits only already-public key
  material and client-signed checkpoint notes.
- BYOK: the checkpoint signing key is read locally at sign time. It is never
  copied into config, never logged, and never sent to the server. The server
  only verifies.
- Credentials: the bearer token is stored `0600` or read from `MOSSKEYS_TOKEN`,
  and is redacted in all output.
- Supply chain: releases are built `--locked`, scanned with `cargo audit`, ship
  a CycloneDX SBOM and `SHA512SUMS`, and are signed with keyless cosign plus a
  SLSA build-provenance attestation. See [RELEASING.md](RELEASING.md) to verify
  a download.
