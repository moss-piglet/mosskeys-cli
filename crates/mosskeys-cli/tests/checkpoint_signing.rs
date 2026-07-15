//! End-to-end signed-checkpoint coverage with a REAL hybrid keypair.
//!
//! These are the tests the #60b Elixir suite could not write under its
//! "no new deps" constraint: they generate a genuine composite hybrid signing
//! key via `metamorphic-crypto`, drive the CLI's local BYOK signing path
//! (`mosskeys_core::signing`), and then verify the produced C2SP note through
//! the SAME `metamorphic-log` verifier the server uses. Because both sides link
//! the one native core, a pass here means a note the CLI signs is exactly what
//! the server will accept — the honest, hermetic proof of the Option-C posture.
//!
//! Two required paths are covered:
//!   * verify-success — a correctly signed note verifies + parses to the exact
//!     head material (`size`/`root`) that was signed;
//!   * head-mismatch — the signed note commits to the head it was signed for and
//!     NOT to a divergent server head, which is precisely the invariant the
//!     server's Phase-2 head-match assertion enforces (409).
//!
//! A tamper-evidence check rounds it out: mutating the signed body breaks
//! verification.

use base64::Engine as _;
use metamorphic_crypto::generate_signing_keypair;
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::note::VerifierKey;
use mosskeys_core::CheckpointMaterial;
use mosskeys_core::signing::sign_material;

const ORIGIN: &str = "mosskeys.com/demo";
const NAME: &str = "mosskeys.com/demo";

fn root_b64(byte: u8) -> String {
    base64::engine::general_purpose::STANDARD.encode([byte; 32])
}

fn material(size: u64, root_byte: u8) -> CheckpointMaterial {
    CheckpointMaterial {
        origin: ORIGIN.to_string(),
        name: NAME.to_string(),
        size,
        root: root_b64(root_byte),
    }
}

/// Build the hybrid verifier key that matches a composite secret key, exactly
/// as the server derives it from the namespace's stored public key.
fn verifier_for(secret_key_b64: &str) -> VerifierKey {
    let public_key_b64 = metamorphic_crypto::derive_public_key(secret_key_b64).unwrap();
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .unwrap();
    VerifierKey::new_hybrid(NAME, &public_key).unwrap()
}

#[test]
fn verify_success_signed_note_matches_head() {
    let kp = generate_signing_keypair();
    let mat = material(42, 7);

    let note_text = sign_material(&mat, &kp.secret_key).expect("local BYOK signing");

    // The server's verify path: parse + verify the signed note against the
    // namespace public key, then read back the committed head.
    let vkey = verifier_for(&kp.secret_key);
    let checkpoint = Checkpoint::from_signed_note(&note_text, &[vkey])
        .expect("server accepts the CLI-signed note");

    assert_eq!(checkpoint.origin(), ORIGIN);
    assert_eq!(
        checkpoint.size(),
        42,
        "committed size must equal signed head"
    );

    let expected_root = base64::engine::general_purpose::STANDARD
        .decode(mat.root)
        .unwrap();
    assert_eq!(
        checkpoint.root_hash().as_slice(),
        expected_root.as_slice(),
        "committed root must equal signed head"
    );
}

#[test]
fn head_mismatch_note_commits_to_signed_head_not_server_head() {
    let kp = generate_signing_keypair();

    // Client signs the head it saw in Phase 1 (size 10, root 0x01…).
    let signed = material(10, 1);
    let note_text = sign_material(&signed, &kp.secret_key).unwrap();

    // Meanwhile the server's current head has advanced (size 11, root 0x02…).
    let server_head = material(11, 2);
    let server_root = base64::engine::general_purpose::STANDARD
        .decode(&server_head.root)
        .unwrap();

    // The verified note commits to the SIGNED head, never the divergent server
    // head — this is exactly what the Phase-2 head-match assertion checks, so
    // publishing this note against the advanced head is a 409 head_mismatch.
    let vkey = verifier_for(&kp.secret_key);
    let checkpoint = Checkpoint::from_signed_note(&note_text, &[vkey]).unwrap();

    assert_eq!(checkpoint.size(), 10);
    assert_ne!(
        checkpoint.size(),
        server_head.size,
        "signed head must differ from the advanced server head"
    );
    assert_ne!(
        checkpoint.root_hash().as_slice(),
        server_root.as_slice(),
        "signed root must not match the advanced server root (drives 409)"
    );
}

#[test]
fn tampered_note_fails_verification() {
    let kp = generate_signing_keypair();
    let note_text = sign_material(&material(5, 9), &kp.secret_key).unwrap();

    // Flip a byte in the checkpoint body (the size line): the signature no
    // longer verifies, so the server rejects it.
    let tampered = note_text.replacen('5', "6", 1);
    assert_ne!(tampered, note_text);

    let vkey = verifier_for(&kp.secret_key);
    assert!(
        Checkpoint::from_signed_note(&tampered, &[vkey]).is_err(),
        "a tampered note must not verify"
    );
}

#[test]
fn wrong_key_fails_verification() {
    let signer = generate_signing_keypair();
    let attacker = generate_signing_keypair();
    let note_text = sign_material(&material(5, 3), &signer.secret_key).unwrap();

    // Verifying against a DIFFERENT namespace key fails — the server only trusts
    // the namespace's own public key.
    let wrong_vkey = verifier_for(&attacker.secret_key);
    assert!(
        Checkpoint::from_signed_note(&note_text, &[wrong_vkey]).is_err(),
        "a note signed by another key must not verify"
    );
}
