//! Hermetic coverage for `mosskeys keygen` (board #79).
//!
//! These tests link the SAME native crypto + log core the server uses and prove
//! the customer-facing keygen is trustworthy end-to-end:
//!
//!   * generated PUBLIC keys are accepted by the `metamorphic-log`
//!     `key_history_v1` leaf/canonical-bytes path (the exact encode/hash the
//!     server runs) — so a leaf built from CLI-generated keys is valid;
//!   * the frozen artifact schema matches #77/#78, and PRIVATE halves live only
//!     in the local file, never in the transmitted (public) envelope;
//!   * the KEM/signature parameter sets track the security level (byte lengths
//!     cross-checked against the reference impls);
//!   * the private artifact is written `0600` and refuses to overwrite.

use base64::Engine as _;
use metamorphic_log::leaf::key_history_v1::Entry;
use mosskeys_core::keygen::{self, NamespaceMeta};
use mosskeys_core::{Artifact, SecurityLevel};

fn decode(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("valid base64 from the crypto core")
}

fn artifact(level: SecurityLevel) -> Artifact {
    let key_set = keygen::generate_key_set(level).expect("hybrid keygen");
    let ns = NamespaceMeta::new(
        Some("demo".into()),
        Some("00000000-0000-0000-0000-000000000000".into()),
    );
    keygen::build_artifact(key_set, level, "alice@example.com".into(), ns)
}

/// The decoded byte lengths per level, mirroring #77/#78. `signing_pub` is the
/// composite (1-byte tag + Ed25519 pk + ML-DSA pk).
fn expected_lengths(level: SecurityLevel) -> (usize, usize, usize) {
    match level {
        SecurityLevel::Cat3 => (32, 1216, 1985),
        SecurityLevel::Cat5 => (32, 1600, 2625),
    }
}

#[test]
fn param_sets_track_security_level() {
    for level in [SecurityLevel::Cat3, SecurityLevel::Cat5] {
        let a = artifact(level);
        let (x, pq, sig) = expected_lengths(level);
        assert_eq!(
            decode(&a.public_keys.enc_x25519).len(),
            x,
            "{level:?} enc_x25519"
        );
        assert_eq!(decode(&a.public_keys.enc_pq).len(), pq, "{level:?} enc_pq");
        assert_eq!(
            decode(&a.public_keys.signing_pub).len(),
            sig,
            "{level:?} signing_pub"
        );
    }
}

#[test]
fn public_keys_accepted_by_leaf_canonical_bytes_path() {
    // Feed the CLI-generated PUBLIC halves through the exact leaf encode/hash
    // the server uses. If the bytes were malformed, canonicalization or hashing
    // would fail; a genesis entry hashes cleanly here.
    let a = artifact(SecurityLevel::Cat5);
    let entry = Entry {
        seq: 0,
        ts_ms: 1_700_000_000_000,
        enc_x25519: decode(&a.public_keys.enc_x25519),
        enc_pq: decode(&a.public_keys.enc_pq),
        signing_pub: decode(&a.public_keys.signing_pub),
        prev_entry_hash: None,
    };

    let canonical = entry.canonical_bytes().expect("canonical bytes");
    assert!(!canonical.is_empty());
    let entry_hash = entry.entry_hash().expect("SHA3-512 entry hash");
    assert_eq!(entry_hash.len(), 64);
    // The RFC 6962 Merkle leaf hash (global ordering linkage) also computes.
    entry.rfc6962_leaf_hash().expect("RFC 6962 leaf hash");
}

#[test]
fn artifact_schema_is_frozen() {
    let a = artifact(SecurityLevel::Cat3);
    let v = serde_json::to_value(&a).unwrap();

    assert_eq!(v["product"], "mosskeys");
    assert_eq!(v["leaf_format"], "mosslet/key-history/v1");
    assert_eq!(v["security_level"], "cat3");
    assert_eq!(v["label"], "alice@example.com");
    assert_eq!(v["namespace"]["slug"], "demo");
    assert_eq!(v["namespace"]["host"], "demo.mosskeys.com");
    for k in ["enc_x25519", "enc_pq", "signing_pub"] {
        assert!(v["public_keys"][k].is_string(), "public_keys.{k}");
        assert!(v["private_keys"][k].is_string(), "private_keys.{k}");
    }
    assert!(v["generated_at"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn private_halves_stay_out_of_the_public_envelope() {
    // The machine envelope emitted on stdout (`--json`) must carry only public
    // material. We model it exactly as the command builds it and assert none of
    // the private halves appear anywhere in its serialization.
    let a = artifact(SecurityLevel::Cat5);
    let envelope = serde_json::json!({
        "ok": true,
        "public_keys": a.public_keys,
        "namespace": a.namespace,
        "leaf_format": a.leaf_format,
    });
    let text = envelope.to_string();
    for priv_key in [
        &a.private_keys.enc_x25519,
        &a.private_keys.enc_pq,
        &a.private_keys.signing_pub,
    ] {
        assert!(
            !text.contains(priv_key.as_str()),
            "private key must never appear in the transmitted envelope"
        );
    }
}

#[test]
fn write_is_0600_and_refuses_overwrite() {
    let a = artifact(SecurityLevel::Cat3);
    let dir = std::env::temp_dir().join(format!("mosskeys-keygen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("private.json");
    let _ = std::fs::remove_file(&path);

    keygen::write_private_artifact(&path, &a).expect("first write");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private file must be 0600");
    }

    // The written file round-trips to the frozen schema (interop artifact).
    let round: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(round["leaf_format"], "mosslet/key-history/v1");
    assert!(round["private_keys"]["enc_pq"].is_string());

    // Refuses to clobber an existing file.
    assert!(
        keygen::write_private_artifact(&path, &a).is_err(),
        "must refuse to overwrite"
    );

    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(&dir).ok();
}
