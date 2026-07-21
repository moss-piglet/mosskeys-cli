# Releasing mosskeys-cli

A single `v*` tag ships two things:

1. **crates.io publish**, so `cargo install mosskeys-cli` works (it installs the
   `mosskeys` binary). Both workspace members are published: `mosskeys-core`
   (the SDK) and then `mosskeys-cli` (the binary crate).
2. **Prebuilt, signed binaries** attached to the GitHub Release for every
   supported platform, plus a CycloneDX SBOM and `SHA512SUMS`.

The pipeline follows the supply-chain house style of `metamorphic-crypto` and
`metamorphic-log`: hand-written workflows (no cargo-dist), third-party actions
pinned to a full commit SHA, OIDC trusted publishing (no long-lived registry
token), keyless cosign signatures, and SLSA build-provenance attestations.

> **Naming.** The crate and install name is `mosskeys-cli`
> (`cargo install mosskeys-cli`, `brew install mosskeys-cli`). The command and
> binary is `mosskeys` (`[[bin]] name = "mosskeys"`), so quickstart commands
> stay `mosskeys keygen …`.

## Versioning

Semantic versioning. The workspace shares one version
(`[workspace.package] version` in the root `Cargo.toml`) and both crates release
in lockstep. The Git tag drives the release and must match `Cargo.toml`
(`v0.1.0` and `version = "0.1.0"`). The `guard` job fails fast if they disagree.

## Cutting a release

1. Bump `version` in the root `Cargo.toml`.
2. Run `cargo build` to update `Cargo.lock`, then commit.
3. Tag and push:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. The `Release` workflow runs the quality gates, builds the cross-platform
   binary matrix (signing and attesting each artifact), aggregates the SBOM,
   `SHA512SUMS`, and GitHub Release, and publishes to crates.io.

Re-running a partially failed release is safe: the crates.io publish steps are
idempotent (an already-published version is skipped, not treated as an error).

## Sibling crates and crates.io (dev vs release)

During local co-development the workspace pins `metamorphic-log` and
`metamorphic-crypto` to sibling working trees (`../metamorphic-*`) with a `path`
key on the workspace dependencies and a `[patch.crates-io]` override, so both
members share exactly one crypto core.

Those paths do not exist on a CI runner and must not influence a published
release. Before any build or publish, CI runs
[`.github/scripts/decouple-from-siblings.sh`](.github/scripts/decouple-from-siblings.sh),
which strips the `path` keys and deletes `[patch.crates-io]`, leaving plain
crates.io version requirements. The deps are already published at the pinned
versions (`metamorphic-crypto 0.10.5`, `metamorphic-log 0.1.10`), so the graph
resolves cleanly. The workflow then re-pins just those two crates into
`Cargo.lock` (`cargo update -p <crate> --precise <version>`) so `--locked` stays
honest for the rest of the tree.

## Supply-chain controls

| Control | Where |
|---|---|
| `cargo fmt --check`, `clippy -D warnings`, tests | CI and release `guard` |
| MSRV (1.85) `--locked` build | CI `msrv` |
| RustSec advisory scan (`cargo audit`) | CI and release `guard` |
| CycloneDX SBOM | release `sbom.json` |
| SHA-512 checksums | release `SHA512SUMS` |
| Keyless cosign `sign-blob --bundle` (per artifact and SBOM) | release |
| SLSA build-provenance attestation | release (per artifact) |
| crates.io OIDC trusted publish (protected `release` env) | release `publish` |

## Verifying a download

```sh
# checksum
sha512sum -c SHA512SUMS

# cosign signature (keyless; the identity is the GitHub Actions release workflow)
cosign verify-blob \
  --bundle mosskeys-<version>-<target>.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/moss-piglet/mosskeys-cli/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mosskeys-<version>-<target>.tar.gz

# build provenance
gh attestation verify mosskeys-<version>-<target>.tar.gz \
  --repo moss-piglet/mosskeys-cli
```

## Homebrew

Shipped as a tap. `brew install mosskeys-cli` installs the `mosskeys` binary from
the signed GitHub Release tarball (the prebuilt artifact, not a from-source
build), so Homebrew users get the same SBOM-tracked, cosign-signed, provenance-
attested binary as a direct download.

- tap repo: `moss-piglet/homebrew-mosskeys-cli`
- formula: `Formula/mosskeys-cli.rb` (class `MosskeysCli`)
- install:

  ```sh
  # Recommended: the fully-qualified name trusts and installs just this formula
  # (Homebrew 6+ requires explicit trust for third-party taps).
  brew install moss-piglet/mosskeys-cli/mosskeys-cli

  # Or tap first, then trust the formula before the short name resolves:
  brew tap moss-piglet/mosskeys-cli
  brew trust --formula moss-piglet/mosskeys-cli/mosskeys-cli
  brew install mosskeys-cli
  ```

The formula is regenerated on every `v*` tag by the release workflow's
`update-tap` job, which runs
[`.github/scripts/render-homebrew-formula.sh`](.github/scripts/render-homebrew-formula.sh)
against the freshly published tarballs (computing SHA-256, since Homebrew requires
it while the release standardizes on SHA-512) and pushes the result to the tap
repo. The canonical copy of the current formula also lives in-repo at
[`packaging/homebrew/mosskeys-cli.rb`](packaging/homebrew/mosskeys-cli.rb).

### Tap security model

`brew install` trusts only the formula's `url` + `sha256`; it does not run
cosign, the SBOM, or the SLSA attestation. Write access to the tap is therefore
release-critical, so the tap is hardened the same way as this repo, with one
adjustment for automation:

- `main` ruleset: block deletion and force-push, require signed commits, and
  require a reviewed PR (1 approval). Human changes always go through review.
- The release automation is a **GitHub App** (contents:write, installed on ONLY
  the tap repo) added as a **bypass actor** on that ruleset, so `update-tap` can
  push the formula bump directly while humans cannot.
- `update-tap` mints a **short-lived** App installation token at runtime
  (auto-expires ~1h, scoped to the single tap repo). No long-lived cross-repo PAT
  is stored anywhere. The App credentials live in the protected `release`
  environment, so only the tag-triggered release job can mint a token.
- Enable secret scanning + push protection and Dependabot on the tap, and keep
  org write access least-privilege.

One-time setup, before the first tag that should update the tap:

1. Create the tap repo `moss-piglet/homebrew-mosskeys-cli` with a `Formula/`
   directory and seed `Formula/mosskeys-cli.rb` (copy `packaging/homebrew/mosskeys-cli.rb`).
2. Register a GitHub App (owner `moss-piglet`) with repository permission
   **Contents: Read and write**, generate a private key, and install the App on
   ONLY `homebrew-mosskeys-cli`.
3. Add two secrets to the `release` environment of `moss-piglet/mosskeys-cli`:
   `HOMEBREW_TAP_APP_ID` (the App's numeric ID) and `HOMEBREW_TAP_APP_PRIVATE_KEY`
   (the full `.pem` contents).
4. On the tap repo, create the `main` ruleset above and add the App as a bypass
   actor; enable secret scanning + push protection and Dependabot.
