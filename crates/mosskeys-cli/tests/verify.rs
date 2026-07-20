//! End-to-end coverage for the read-only `mosskeys verify` path.
//!
//! These tests exercise the `mosskeys-core` verify wrappers with REAL Merkle
//! trees and REAL hybrid + Ed25519 keys, through the SAME `metamorphic-log`
//! verifier the server, browser (WASM), and native SDKs use. Because there is
//! ZERO new crypto in the verify path (it is pure read-path plumbing over the
//! linked core), a pass here means the CLI verifies byte-for-byte what everyone
//! else does.
//!
//! Three required scenarios, matching the #107 acceptance criteria:
//!   * happy path — a valid inclusion proof + a valid, co-signed checkpoint;
//!   * head-mismatch — a consistency proof against a divergent head fails with
//!     the [`VerifyError::Consistency`] outcome (the rewritten-history signal);
//!   * offline pinned checkpoint — parse a pinned checkpoint note and verify
//!     append-only continuity to a newer head with no network at all.

use base64::Engine as _;
use metamorphic_crypto::{ed25519_generate_keypair, generate_signing_keypair};
use metamorphic_log::checkpoint::Checkpoint;
use metamorphic_log::merkle::MerkleTree;
use metamorphic_log::note::{SignedNote, VerifierKey, sign_ed25519, sign_hybrid};

use mosskeys_core::{
    VerifyError, parse_checkpoint_head, verify_consistency, verify_inclusion, verify_witness_cosigs,
};

const ORIGIN: &str = "mosskeys.com/demo";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_nodes(nodes: &[[u8; 32]]) -> Vec<String> {
    nodes.iter().map(|n| b64(n)).collect()
}

/// A tree of `n` distinct leaves (`leaf-0`, `leaf-1`, …).
fn tree_of(n: u64) -> MerkleTree {
    let mut t = MerkleTree::new();
    for i in 0..n {
        t.push(format!("leaf-{i}").as_bytes());
    }
    t
}

/// Sign a checkpoint over `(size, root)` with the log's own hybrid key
/// (`name == origin`), returning the C2SP signed-note text.
fn signed_checkpoint(size: u64, root: &[u8; 32], secret_key_b64: &str) -> String {
    metamorphic_log::checkpoint::sign_checkpoint_hybrid(
        ORIGIN,
        size,
        &b64(root),
        ORIGIN,
        secret_key_b64,
    )
    .expect("hybrid checkpoint signing")
}

fn hybrid_vkey(secret_key_b64: &str) -> String {
    let pk_b64 = metamorphic_crypto::derive_public_key(secret_key_b64).unwrap();
    let pk = base64::engine::general_purpose::STANDARD
        .decode(pk_b64)
        .unwrap();
    VerifierKey::new_hybrid(ORIGIN, &pk).unwrap().encode()
}

#[test]
fn happy_path_inclusion_and_cosigned_checkpoint() {
    let tree = tree_of(50);
    let size = tree.size();
    let index = 42;

    let leaf_hash = tree.leaf_hash(index).unwrap();
    let proof = b64_nodes(&tree.inclusion_proof(index, size));
    let root = tree.root_at(size);

    // Inclusion verifies against the checkpoint root.
    verify_inclusion(index, size, &b64(&leaf_hash), &proof, &b64(&root))
        .expect("valid inclusion proof must verify");

    // The checkpoint is co-signed by the log's own hybrid key; pinning that key
    // as a verifier key verifies the signature and reports the suite.
    let kp = generate_signing_keypair();
    let note = signed_checkpoint(size, &root, &kp.secret_key);
    let report = verify_witness_cosigs(&note, &[hybrid_vkey(&kp.secret_key)])
        .expect("co-signature must verify against the pinned key");
    assert_eq!(report.verified, 1);
    assert_eq!(report.witnesses, 0, "the log's own key is not a witness");
    let suite = report
        .suite
        .expect("a verified hybrid line reports a suite");
    assert!(suite.contains("hybrid"), "suite was {suite:?}");
    assert!(suite.contains("ML-DSA"), "suite was {suite:?}");
}

#[test]
fn independent_witness_is_counted_as_a_witness() {
    // Assemble a checkpoint co-signed by BOTH the log's hybrid key (name =
    // origin) and an independent Ed25519 witness (a different name) — the
    // scenario the landing hero illustrates.
    let tree = tree_of(10);
    let size = tree.size();
    let root = tree.root_at(size);
    let body = Checkpoint::new(ORIGIN, size, root).unwrap().marshal();

    let log_kp = generate_signing_keypair();
    let log_sig = sign_hybrid(&body, ORIGIN, &log_kp.secret_key).unwrap();

    let (witness_seed, witness_pk) = ed25519_generate_keypair();
    let witness_name = "witness.example.com";
    let witness_sig = sign_ed25519(&body, witness_name, &witness_seed).unwrap();

    let note = SignedNote::new(body, vec![log_sig, witness_sig])
        .unwrap()
        .marshal();

    let log_vkey = hybrid_vkey(&log_kp.secret_key);
    let witness_vkey = VerifierKey::new_ed25519(witness_name, &witness_pk)
        .unwrap()
        .encode();

    let report =
        verify_witness_cosigs(&note, &[log_vkey, witness_vkey]).expect("both signatures verify");
    assert_eq!(report.verified, 2);
    assert_eq!(report.witnesses, 1, "one independent witness co-signed");
}

#[test]
fn head_mismatch_consistency_fails() {
    // A genuine append-only extension verifies …
    let tree = tree_of(100);
    let (size1, size2) = (40, 100);
    let proof = b64_nodes(&tree.consistency_proof(size1, size2));
    let root1 = tree.root_at(size1);
    let root2 = tree.root_at(size2);
    verify_consistency(size1, size2, &proof, &b64(&root1), &b64(&root2))
        .expect("a valid consistency proof must verify");

    // … but the SAME proof against a DIVERGENT head (a tree with different
    // leaf contents at the same size) fails as a rewritten head — exactly the
    // equivocation signal.
    let mut divergent = MerkleTree::new();
    for i in 0..size2 {
        divergent.push(format!("rewritten-{i}").as_bytes());
    }
    let bad_root2 = divergent.root_at(size2);
    let err = verify_consistency(size1, size2, &proof, &b64(&root1), &b64(&bad_root2))
        .expect_err("a divergent head must fail consistency");
    assert!(
        matches!(
            err,
            mosskeys_core::Error::Verification(VerifyError::Consistency)
        ),
        "expected a consistency (head-mismatch) failure, got {err:?}"
    );
}

#[test]
fn offline_pinned_checkpoint_verifies_continuity() {
    // Simulate: earlier we pinned a signed checkpoint at size1; now we are
    // handed a newer signed checkpoint at size2 plus a consistency proof — all
    // verified with NO network.
    let tree = tree_of(200);
    let (size1, size2) = (64, 200);
    let kp = generate_signing_keypair();

    let pinned_note = signed_checkpoint(size1, &tree.root_at(size1), &kp.secret_key);
    let head_note = signed_checkpoint(size2, &tree.root_at(size2), &kp.secret_key);

    // Parse both heads out of their notes (the offline entry point).
    let pinned = parse_checkpoint_head(&pinned_note).unwrap();
    let head = parse_checkpoint_head(&head_note).unwrap();
    assert_eq!(pinned.size, size1);
    assert_eq!(head.size, size2);

    // Verify append-only continuity from the pinned root to the head root.
    let proof = b64_nodes(&tree.consistency_proof(size1, size2));
    verify_consistency(
        pinned.size,
        head.size,
        &proof,
        &pinned.root_b64,
        &head.root_b64,
    )
    .expect("offline consistency from pinned to head must verify");

    // And the head note itself is validly signed by the pinned verifier key.
    let report = verify_witness_cosigs(&head_note, &[hybrid_vkey(&kp.secret_key)]).unwrap();
    assert_eq!(report.verified, 1);
}

#[test]
fn wrong_verifier_key_fails_cosig() {
    let tree = tree_of(5);
    let size = tree.size();
    let signer = generate_signing_keypair();
    let attacker = generate_signing_keypair();
    let note = signed_checkpoint(size, &tree.root_at(size), &signer.secret_key);

    let err = verify_witness_cosigs(&note, &[hybrid_vkey(&attacker.secret_key)])
        .expect_err("a note signed by another key must not verify");
    assert!(
        matches!(
            err,
            mosskeys_core::Error::Verification(VerifyError::WitnessCosig)
        ),
        "expected a witness-cosig failure, got {err:?}"
    );
}

#[test]
fn tampered_inclusion_proof_fails() {
    let tree = tree_of(30);
    let size = tree.size();
    let index = 7;
    let leaf_hash = tree.leaf_hash(index).unwrap();
    let proof = b64_nodes(&tree.inclusion_proof(index, size));
    // Verify against the WRONG root (a different tree size): must fail.
    let wrong_root = tree.root_at(size - 1);
    let err = verify_inclusion(index, size, &b64(&leaf_hash), &proof, &b64(&wrong_root))
        .expect_err("inclusion against a wrong root must fail");
    assert!(
        matches!(
            err,
            mosskeys_core::Error::Verification(VerifyError::Inclusion)
        ),
        "expected an inclusion failure, got {err:?}"
    );
}
