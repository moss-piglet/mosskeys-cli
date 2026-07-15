#!/usr/bin/env bash
# Decouple the workspace from its sibling working trees so a CI / release build
# resolves `metamorphic-log` / `metamorphic-crypto` from crates.io instead of
# `../metamorphic-*`.
#
# During local co-development the workspace `Cargo.toml` pins those crates to
# sibling checkouts via `path = "..."` on the workspace dependencies AND a
# `[patch.crates-io]` override, so both members share exactly ONE crypto core.
# `Cargo.lock` therefore records them as source-less (local) packages. None of
# that can exist on a CI runner or influence a published release, so this script
# rewrites both files in place:
#
#   Cargo.toml
#     1. drop the `path = "..."` key from the two sibling workspace dependencies
#        (leaving the crates.io `version` requirement intact), and
#     2. delete the `[patch.crates-io]` table entirely.
#
#   Cargo.lock
#     3. delete the source-less metamorphic-* package entries so they get re-added
#        FROM crates.io (with a registry source + checksum) by `cargo fetch`.
#        Only these two entries are touched; every other dependency stays pinned
#        exactly as committed, which is what keeps the `--locked` build honest and
#        avoids resolver drift into incompatible pre-release transitive deps.
#
# The published deps are already on crates.io at the pinned versions
# (metamorphic-crypto 0.10.5, metamorphic-log 0.1.10). After this script, run
# `cargo fetch` once to re-add the two entries, then build/publish with `--locked`.
#
# Idempotent: safe to run twice (the second run is a no-op).
set -euo pipefail

manifest="${1:-Cargo.toml}"
lockfile="${2:-Cargo.lock}"

python3 - "$manifest" "$lockfile" <<'PY'
import re, sys

manifest, lockfile = sys.argv[1], sys.argv[2]

# --- Cargo.toml ---
src = open(manifest, encoding="utf-8").read()

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

open(manifest, "w", encoding="utf-8").write(src)
print(f"decoupled {manifest} from sibling working trees")

# --- Cargo.lock ---
try:
    lock = open(lockfile, encoding="utf-8").read()
except FileNotFoundError:
    print(f"no {lockfile}; skipping lock cleanup")
    raise SystemExit(0)

for name in ("metamorphic-crypto", "metamorphic-log"):
    lock = re.sub(
        r'\[\[package\]\]\nname = "%s"\n.*?(?=\n\[\[package\]\]|\Z)' % re.escape(name),
        "",
        lock,
        flags=re.S,
    )

open(lockfile, "w", encoding="utf-8").write(lock)
print(f"removed metamorphic-* entries from {lockfile} (cargo fetch re-adds from crates.io)")
PY

echo "--- resulting [workspace.dependencies] + patch state ---"
grep -nE 'metamorphic-(log|crypto)|\[patch' "$manifest" || true
