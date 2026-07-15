#!/usr/bin/env bash
# Decouple the workspace from its sibling working trees so a CI / release build
# resolves `metamorphic-log` / `metamorphic-crypto` from crates.io instead of
# `../metamorphic-*`.
#
# During local co-development the workspace `Cargo.toml` pins those crates to
# sibling checkouts via `path = "..."` on the workspace dependencies AND a
# `[patch.crates-io]` override, so both members share exactly ONE crypto core.
# Those paths do not exist on a CI runner (and MUST NOT influence a published
# release), so this script rewrites `Cargo.toml` in place to:
#
#   1. drop the `path = "..."` key from the two sibling workspace dependencies
#      (leaving the crates.io `version` requirement intact), and
#   2. delete the `[patch.crates-io]` table entirely.
#
# The published deps are already on crates.io at the pinned versions
# (metamorphic-crypto 0.10.5, metamorphic-log 0.1.10), so the result is a clean,
# fully crates.io-resolved graph. Run before `cargo build`/`cargo publish` in CI.
#
# Idempotent: safe to run twice (the second run is a no-op).
set -euo pipefail

manifest="${1:-Cargo.toml}"

python3 - "$manifest" <<'PY'
import re, sys

path = sys.argv[1]
src = open(path, encoding="utf-8").read()

# 1. Strip `, path = "../metamorphic-*"` from the workspace dependency lines,
#    keeping the crates.io version requirement.
src = re.sub(
    r'(metamorphic-(?:log|crypto)\s*=\s*\{[^}]*?),\s*path\s*=\s*"\.\./metamorphic-[a-z]+"',
    r'\1',
    src,
)

# 2. Remove the [patch.crates-io] table (and any comment block directly above
#    it) through EOF or the next table header.
src = re.sub(
    r'\n(?:#[^\n]*\n)*\[patch\.crates-io\][^\[]*(?=\n\[|\Z)',
    '\n',
    src,
)

open(path, "w", encoding="utf-8").write(src)
print(f"decoupled {path} from sibling working trees")
PY

echo "--- resulting [workspace.dependencies] + patch state ---"
grep -nE 'metamorphic-(log|crypto)|\[patch' "$manifest" || true
