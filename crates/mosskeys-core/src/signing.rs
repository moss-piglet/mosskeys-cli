//! Local, offline BYOK checkpoint signing.
//!
//! This is the crux of the Option-C zero-knowledge posture: the operator holds
//! the composite hybrid signing key on *their* infrastructure, and this module
//! turns Phase-1 [`CheckpointMaterial`] into the C2SP signed-note `note_text`
//! that Phase 2 publishes. The key is read here, used here, and dropped here —
//! it is never sent to the server (the server only ever *verifies*).
//!
//! The signing itself is delegated wholesale to `metamorphic-log`'s
//! [`sign_checkpoint_dual`], the SAME core the browser WASM and the Elixir NIF
//! use, so a note signed by the CLI verifies byte-for-byte server-side. The
//! dual-line note carries the additive hybrid post-quantum line PLUS a
//! classical Ed25519 (`0x01`) line under the same key name, so stock
//! Ed25519-only C2SP witness software can verify and cosign the checkpoint
//! while every existing verifier keeps working (unknown-key lines are ignored).

use std::path::Path;

use metamorphic_log::checkpoint::sign_checkpoint_dual;

use crate::client::CheckpointMaterial;
use crate::error::{Error, Result};

/// Read the base64 composite secret key from `path`, trimming surrounding
/// whitespace/newlines. The bytes never leave this process.
///
/// # Errors
/// Fails if the file cannot be read.
pub fn read_signing_key(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Io(format!("reading signing key {}: {e}", path.display())))?;
    Ok(raw.trim().to_string())
}

/// Sign Phase-1 `material` with the composite `secret_key_b64`, returning the
/// complete dual-line C2SP signed-note text (hybrid + Ed25519 `0x01` under the
/// same key name) ready to POST as `note_text` in Phase 2.
///
/// # Errors
/// Returns [`Error::Signing`] if the material or key is malformed, the key has
/// no Ed25519 classical half (matched-suite / pure-PQ), or signing fails.
pub fn sign_material(material: &CheckpointMaterial, secret_key_b64: &str) -> Result<String> {
    sign_checkpoint_dual(
        &material.origin,
        material.size,
        &material.root,
        &material.name,
        secret_key_b64,
    )
    .map_err(|e| Error::Signing(e.to_string()))
}
