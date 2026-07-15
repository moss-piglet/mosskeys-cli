# mosskeys-cli

The [MossKeys](https://mosskeys.app) command-line interface + daemon.

Publish public key material to a namespace's transparency log and sign
checkpoints **locally** (BYOK) against the owner-scoped write API. Written in
Rust; links the `metamorphic-log` / `metamorphic-crypto` core natively, so it
ships as a single static binary and shares one audited crypto stack with the web
(WASM) and Elixir (NIF) surfaces.

> **Zero-knowledge posture.** The CLI transmits only already-public material and
> client-signed checkpoint notes. The checkpoint signing key is read locally,
> used locally, and never logged or sent to the server — the server only ever
> *verifies* (Option C).

## Layout

```
crates/
  mosskeys-core/   # write-API client, config, typed errors, local BYOK signing (reusable SDK crate)
  mosskeys-cli/    # the `mosskeys` binary: clap commands, brand theme, output
```

## Commands

| Command | Purpose |
|---|---|
| `mosskeys keygen` | Generate a `mosslet/key-history/v1` key set **locally** (BYOK). Writes the private halves to a `0600` file (refuses to overwrite) and prints only the public halves. Byte-for-byte interoperable with the browser + Mix reference impls. |
| `mosskeys publish` | Append one/many public-key entries (flags, `--file`, or stdin JSON). Idempotent. |
| `mosskeys sync` | Daemon: watch a JSON source and continuously publish. At-least-once via server dedup, with backoff/retry. |
| `mosskeys checkpoint` | Two-phase local BYOK signing: fetch head → sign offline → publish (server verifies + head-match). `--watch` for a cadence. |
| `mosskeys config …` | Manage credentials + defaults (`~/.config/mosskeys/config.toml`, `MOSSKEYS_TOKEN` / `MOSSKEYS_BASE_URL` env). |

Global flags: `--json` (machine output for agents/scripts), `--namespace/-n`,
`--base-url`, `--config`, plus per-command `--dry-run`. Stable exit codes map the
API error taxonomy (`unauthorized`, `forbidden`, `not_found`, `head_mismatch`,
`invalid_request`, `rate_limited`). Colour honours `NO_COLOR` / non-TTY / `--json`.

## Quickstart

```sh
# 1. Generate your identity's key set locally (keys never leave this machine).
#    The private halves land in mosskeys-<slug>-<label>-private-keys.json (0600).
mosskeys keygen --namespace acme --security-level cat5 --label alice@acme.com

# 2. Publish the PUBLIC halves printed above to your namespace's log.
mosskeys publish --namespace acme --label alice@acme.com \
  --enc-x25519 <base64> --enc-pq <base64> --signing-pub <base64>
```

`keygen` is fully offline — it never contacts the server, so `--security-level`
is operator-supplied (match it to your namespace's declared policy).

## Build & test

```sh
cargo build --release        # → target/release/mosskeys (single static binary)
cargo test                   # hermetic signing e2e + contract unit tests
cargo clippy --all-targets
```

The signing e2e tests generate a real hybrid keypair via `metamorphic-crypto`
and verify a CLI-signed note through the same `metamorphic-log` verifier the
server uses — proving verify-success and head-mismatch semantics without a live
server. The keygen tests feed CLI-generated public keys through the same
`metamorphic-log` `key_history_v1` leaf/canonical-bytes path the server runs,
cross-check the per-level byte lengths, and assert private halves never appear
in the transmitted envelope.

## Local development

The `metamorphic-log` / `metamorphic-crypto` deps resolve to sibling working
trees (`../metamorphic-log`, `../metamorphic-crypto`); a `[patch.crates-io]` in
the workspace `Cargo.toml` pins a single crypto core across the graph.

## License

MIT OR Apache-2.0.
