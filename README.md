# mosskeys-cli

The [mosskeys](https://mosskeys.com) command-line interface and daemon.

Publish public key material to a namespace's transparency log, sign checkpoints
**locally** (BYOK), and **verify** key-history proofs read-only and offline
against the public API. Written in Rust, it links the `metamorphic-log` and
`metamorphic-crypto` core natively, so it ships as a single static binary and
shares one audited crypto stack with the web (WASM) and Elixir (NIF) surfaces.

> **Zero-knowledge security profile.** The CLI transmits only already-public
> material and client-signed checkpoint notes. The checkpoint signing key is
> read locally, used locally, and never logged or sent to the server. The server
> only ever verifies (Option C).

The package name is `mosskeys-cli`; the command it installs is `mosskeys`.

## Install

```sh
cargo install mosskeys-cli --locked   # installs the `mosskeys` binary
```

Use `--locked` so the build uses the versions pinned in the published
`Cargo.lock`. The crypto core depends on pre-release RustCrypto curve crates,
and a fresh resolve without `--locked` can pick an incompatible newer
transitive release. Prebuilt binaries (below) are already built and are
unaffected.

On macOS, Homebrew installs the same prebuilt, signed binary from a tap:

```sh
brew install moss-piglet/mosskeys-cli/mosskeys-cli
```

The fully-qualified name trusts and installs just that formula (Homebrew 6+
requires explicit trust for third-party taps).

Prebuilt, signed binaries for macOS (arm64/x64), Linux (x64/arm64, including
musl), and Windows (x64) are attached to every
[GitHub Release](https://github.com/moss-piglet/mosskeys-cli/releases), each with
a CycloneDX SBOM, `SHA512SUMS`, a cosign signature, and SLSA build provenance.
See [RELEASING.md](RELEASING.md) to verify a download.

## Layout

```
crates/
  mosskeys-core/   # write + read/verify API client, config, typed errors, local BYOK signing (reusable SDK crate)
  mosskeys-cli/    # the `mosskeys` binary: clap commands, brand theme, output
```

## Commands

| Command | Purpose |
|---|---|
| `mosskeys keygen` | Generate a `mosskeys/key-history/v1` key set **locally** (BYOK). Writes the private halves to a `0600` file (refuses to overwrite) and prints only the public halves. Byte-for-byte interoperable with the browser and Mix reference implementations. |
| `mosskeys publish` | Append one or many public-key entries (flags, `--file`, or stdin JSON). Idempotent. |
| `mosskeys sync` | Daemon: watch a JSON source and continuously publish. At-least-once via server dedup, with backoff and retry. |
| `mosskeys checkpoint` | Two-phase local BYOK signing: fetch head, sign offline, publish (server verifies and head-matches). `--watch` runs it on a cadence. |
| `mosskeys verify` | Read-only, offline-capable proof checking (no token). Verifies inclusion, append-only consistency, and witness co-signatures for a `--label` (online), a pinned `--checkpoint` note (offline), or a `--digest` at `--index` (supply-chain). Zero new crypto: every check runs through the same `metamorphic-log` verifier. |
| `mosskeys config …` | Manage credentials and defaults (`~/.config/mosskeys/config.toml`, `MOSSKEYS_TOKEN` and `MOSSKEYS_BASE_URL` env). |

Global flags: `--json` (machine output for agents and scripts), `--namespace/-n`,
`--base-url`, `--config`, plus per-command `--dry-run`. Stable exit codes map the
API error taxonomy (`unauthorized`, `forbidden`, `not_found`, `head_mismatch`,
`invalid_request`, `rate_limited`) plus the `verify` outcomes (a failed
consistency proof shares `head_mismatch`; other verification failures use a
dedicated code). Colour honours `NO_COLOR`, non-TTY, and `--json`.

## Quickstart

```sh
# 1. Generate your identity's key set locally (keys never leave this machine).
#    The private halves land in mosskeys-<slug>-<label>-private-keys.json (0600).
mosskeys keygen --namespace acme --security-level cat5 --label alice@acme.com

# 2. Publish the PUBLIC halves printed above to your namespace's log.
mosskeys publish --namespace acme --label alice@acme.com \
  --enc-x25519 <base64> --enc-pq <base64> --signing-pub <base64>

# 3. Anyone can verify that label's key history — no token, no account.
mosskeys verify --namespace acme --label alice@acme.com
```

`keygen` is fully offline and never contacts the server, so `--security-level`
is operator-supplied. Match it to your namespace's declared policy.

`verify` proves that, in an append-only log, the history you are shown has not
been rewritten (inclusion + consistency + witness co-signatures). Pin trusted
keys with `--verifier-key` to check co-signatures, and a prior `--checkpoint`
note with `--pin` to prove append-only continuity. It does **not**, on its own,
detect a split view (the log serving a different head to someone else); that
needs independent witnesses observing the same head.

## Build and test

```sh
cargo build --release        # target/release/mosskeys (single static binary)
cargo test                   # hermetic signing e2e + contract unit tests
cargo clippy --all-targets
```

The signing e2e tests generate a real hybrid keypair via `metamorphic-crypto`
and verify a CLI-signed note through the same `metamorphic-log` verifier the
server uses, proving verify-success and head-mismatch semantics without a live
server. The verify e2e tests exercise the read-path checks end to end against
real Merkle trees and keys (inclusion, append-only consistency, witness
co-signatures, an independent-witness count, offline pinned-checkpoint
continuity, and the tamper/wrong-key failure paths). The keygen tests feed
CLI-generated public keys through the same `metamorphic-log` `key_history_v1`
leaf and canonical-bytes path the server runs, cross-check the per-level byte
lengths, and assert that private halves never appear in the transmitted
envelope.

## Local development

The `metamorphic-log` and `metamorphic-crypto` deps resolve to sibling working
trees (`../metamorphic-log`, `../metamorphic-crypto`) via a `[patch.crates-io]`
override in the workspace `Cargo.toml`, so both members share one crypto core.
CI and release builds resolve from crates.io instead. See
[RELEASING.md](RELEASING.md#sibling-crates-and-patchcrates-io-dev-vs-release).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option.
