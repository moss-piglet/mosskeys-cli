//! Read-path verification: thin wrappers over the linked `metamorphic-log`
//! verifier.
//!
//! This module adds **zero cryptography of its own**. Every check delegates to
//! `metamorphic-log` (which in turn delegates all primitives to
//! `metamorphic-crypto`) — the same audited core the server, the browser WASM
//! SDK, and the native Swift/Kotlin/Python verifiers use. A proof that verifies
//! here therefore verifies byte-for-byte everywhere.
//!
//! ## What these checks prove, and what they do not
//!
//! Verifying **inclusion** + **consistency** + **witness co-signatures** shows
//! that a label's key history sits in an append-only log whose head has not
//! been rewritten, reordered, or truncated — history is tamper-evident.
//!
//! They do **not**, on their own, detect a *split view* (the log serving one
//! head to you and a different head to someone else). Catching that requires
//! independent witnesses observing and co-signing the same head; the CLI states
//! this plainly in its help rather than overclaiming.

use base64::Engine as _;
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::note::{SignatureType, SignedNote, VerifierKey};

use crate::error::{Error, Result, VerifyError};

fn b64_decode(what: &str, s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| Error::Verification(VerifyError::Malformed(format!("{what} is not base64"))))
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_proof(proof_b64: &[String]) -> Result<Vec<Vec<u8>>> {
    proof_b64
        .iter()
        .map(|node| b64_decode("proof node", node))
        .collect()
}

/// Verify an RFC 6962 / RFC 9162 **inclusion** proof from base64 wire values.
///
/// Proves `leaf_hash` is committed at `index` in the tree of `size` leaves
/// whose head is `root`. Delegates to [`metamorphic_log::verify_inclusion`].
///
/// # Errors
/// [`VerifyError::Malformed`] if any input is not valid base64, or
/// [`VerifyError::Inclusion`] if the proof does not reproduce `root`.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash_b64: &str,
    proof_b64: &[String],
    root_b64: &str,
) -> Result<()> {
    let leaf_hash = b64_decode("leaf hash", leaf_hash_b64)?;
    let proof = decode_proof(proof_b64)?;
    let root = b64_decode("root", root_b64)?;
    metamorphic_log::verify_inclusion(index, size, &leaf_hash, &proof, &root)
        .map_err(|_| Error::Verification(VerifyError::Inclusion))
}

/// Verify an RFC 6962 / RFC 9162 **consistency** proof from base64 wire values.
///
/// Proves the tree of `size2` (head `root2`) is an append-only extension of the
/// tree of `size1` (head `root1`): no earlier entry was modified, reordered, or
/// removed. Delegates to [`metamorphic_log::verify_consistency`].
///
/// # Errors
/// [`VerifyError::Malformed`] if any input is not valid base64, or
/// [`VerifyError::Consistency`] if the proof does not bind both heads (i.e. the
/// log's history was rewritten).
pub fn verify_consistency(
    size1: u64,
    size2: u64,
    proof_b64: &[String],
    root1_b64: &str,
    root2_b64: &str,
) -> Result<()> {
    let proof = decode_proof(proof_b64)?;
    let root1 = b64_decode("pinned root", root1_b64)?;
    let root2 = b64_decode("head root", root2_b64)?;
    metamorphic_log::verify_consistency(size1, size2, &proof, &root1, &root2)
        .map_err(|_| Error::Verification(VerifyError::Consistency))
}

/// The committed head parsed out of a checkpoint signed note.
#[derive(Debug, Clone)]
pub struct CheckpointHead {
    /// The C2SP log origin the checkpoint commits under.
    pub origin: String,
    /// The tree size the checkpoint commits to.
    pub size: u64,
    /// Base64 of the 32-byte RFC 6962 root at `size`.
    pub root_b64: String,
}

/// Parse (but do not signature-verify) the head out of a checkpoint signed
/// note.
///
/// Strips the signature lines and parses the C2SP checkpoint body, returning the
/// committed `origin`/`size`/`root`. Signature verification is a separate,
/// key-bearing step ([`verify_witness_cosigs`]).
///
/// # Errors
/// [`VerifyError::Malformed`] if the note or its checkpoint body is malformed.
pub fn parse_checkpoint_head(note_text: &str) -> Result<CheckpointHead> {
    let note = SignedNote::parse(note_text)
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
    let checkpoint = Checkpoint::parse(note.text())
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
    Ok(CheckpointHead {
        origin: checkpoint.origin().to_string(),
        size: checkpoint.size(),
        root_b64: b64_encode(checkpoint.root_hash().as_slice()),
    })
}

/// The outcome of checking a checkpoint's co-signatures against pinned keys.
#[derive(Debug, Clone)]
pub struct CosignReport {
    /// Total signature lines on the note that verified against a pinned key.
    pub verified: usize,
    /// Of those, how many are independent **witnesses** (a verified signature
    /// whose key name differs from the log's own `origin`).
    pub witnesses: usize,
    /// A human-readable description of the strongest verified signature suite
    /// (for example `ML-DSA-87 + Ed25519 (hybrid)` or `Ed25519`), or `None`
    /// when no hybrid/classical line could be classified.
    pub suite: Option<String>,
}

/// Verify a checkpoint's co-signatures against a set of pinned, trusted verifier
/// keys (C2SP `vkey` strings — the log's own key and/or independent witnesses).
///
/// This is `metamorphic-log`'s note verification, surfaced for the read path: at
/// least one pinned key must have signed the note, every pinned key that *did*
/// sign must verify, and the result reports how many independent witnesses
/// co-signed plus the signature suite. No new crypto — [`SignedNote::verify`]
/// runs the primitives.
///
/// # Errors
/// [`VerifyError::Malformed`] if the note is malformed or a `vkey` cannot be
/// parsed; [`VerifyError::WitnessCosig`] if no pinned key signed the note or a
/// pinned signature failed to verify.
pub fn verify_witness_cosigs(note_text: &str, trusted_vkeys: &[String]) -> Result<CosignReport> {
    let note = SignedNote::parse(note_text)
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
    let checkpoint = Checkpoint::parse(note.text())
        .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))?;
    let origin = checkpoint.origin().to_string();

    let keys: Vec<VerifierKey> = trusted_vkeys
        .iter()
        .map(|k| {
            VerifierKey::parse(k.trim())
                .map_err(|e| Error::Verification(VerifyError::Malformed(e.to_string())))
        })
        .collect::<Result<_>>()?;

    let verified = note
        .verify(&keys)
        .map_err(|_| Error::Verification(VerifyError::WitnessCosig))?;

    let mut witnesses = 0usize;
    let mut best: Option<String> = None;
    for sig in &verified {
        if sig.name() != origin {
            witnesses += 1;
        }
        if let Some(key) = keys
            .iter()
            .find(|k| k.key_id() == sig.key_id() && k.name() == sig.name())
        {
            let label = suite_label(key);
            // Prefer a post-quantum description (hybrid composite, or an
            // ML-DSA-44 witness cosignature) over a classical-only one.
            let prefer = label.contains("hybrid") || label.contains("ML-DSA");
            if best.is_none() || prefer {
                best = Some(label);
            }
        }
    }

    Ok(CosignReport {
        verified: verified.len(),
        witnesses,
        suite: best,
    })
}

/// Describe a verifier key's signature suite honestly, reading the declared
/// posture from the composite public key via `metamorphic-crypto` (never
/// hard-coding a level).
fn suite_label(key: &VerifierKey) -> String {
    match key.signature_type() {
        SignatureType::Ed25519 => "Ed25519".to_string(),
        SignatureType::MetamorphicHybrid => {
            let pk_b64 = b64_encode(key.public_key());
            match metamorphic_crypto::signature_posture(&pk_b64) {
                Ok((_suite, level)) => {
                    format!("{} + Ed25519 (hybrid)", ml_dsa_name(level))
                }
                // The key verified but its posture tag is unknown to this build:
                // report the family without inventing a level.
                Err(_) => "ML-DSA + Ed25519 (hybrid)".to_string(),
            }
        }
        // C2SP tlog-cosignature v1 witness lines: an independent witness co-signs
        // the checkpoint with either a classical Ed25519 or a post-quantum
        // ML-DSA-44 cosignature.
        SignatureType::CosignatureV1Ed25519 => "Ed25519 (witness cosignature)".to_string(),
        SignatureType::CosignatureV1MlDsa44 => {
            "ML-DSA-44 (witness cosignature, post-quantum)".to_string()
        }
    }
}

fn ml_dsa_name(level: metamorphic_crypto::SignatureLevel) -> &'static str {
    use metamorphic_crypto::SignatureLevel::{Cat2, Cat3, Cat5};
    match level {
        Cat2 => "ML-DSA-44",
        Cat3 => "ML-DSA-65",
        Cat5 => "ML-DSA-87",
    }
}
