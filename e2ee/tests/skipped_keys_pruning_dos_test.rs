//! Skipped-Key Expiration, Memory Pruning & DoS Limit Stress Suite
//!
//! Validates:
//! 1. DoS Skip Throttling: Verifies that an adversary attempting to jump sequence numbers
//!    by >100 in a single epoch is blocked with `DoubleRatchetError`, preventing CPU exhaustion.
//! 2. FIFO Memory Pruning: Verifies that cumulative skipped keys across multiple epochs strictly
//!    cap at `MAX_SKIPPED_KEYS` (1000), evicting oldest keys to prevent memory exhaustion.
//! 3. Evicted Key Rejection: Messages corresponding to evicted skipped keys fail to decrypt.
//! 4. Unevicted Key Retrievability: Unevicted skipped keys remain decryptable out of order.
//! 5. One-Time Consumption & Replay Resistance: Once a skipped key is used, it is purged
//!    from memory and cannot be replayed.

extern crate alloc;

use e2ee::{IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair, PreKeyBundle, Session, Message};

fn setup_sessions() -> (Session, Session) {
    let alice_id = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_id = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_id, &[0x33; 32])).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);

    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_id.public_key()),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };

    let (alice_session, prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg)).unwrap();
    let plaintext = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    assert_eq!(plaintext, b"");

    (alice_session, bob_session)
}

#[test]
fn test_single_epoch_skip_dos_throttling() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice generates 150 messages in the current epoch
    let mut messages = Vec::new();
    for i in 0..150 {
        let msg = alice.encrypt_message(&[i as u8; 32]).unwrap();
        messages.push(msg);
    }

    // Adversary delivers message 105 directly (attempting to skip 105 messages in one hop)
    // The ratchet enforces maximum 100 skipped keys per jump to prevent CPU stalling.
    let res = bob.decrypt_message(&messages[105], &[0x71; 32], &[0x72; 64], &[0x73; 32]);
    assert!(res.is_err(), "Ratchet allowed unbounded single-hop skip > 100!");

    // However, jumping 50 messages is within tolerance
    let res_valid = bob.decrypt_message(&messages[50], &[0x71; 32], &[0x72; 64], &[0x73; 32]);
    assert!(res_valid.is_ok(), "Ratchet rejected valid bounded jump of 50 messages!");
    assert_eq!(res_valid.unwrap(), [50u8; 32]);
}

#[test]
fn test_fifo_skipped_key_pruning_and_boundary_retrieval() {
    let (mut alice, mut bob) = setup_sessions();

    // We will accumulate >1000 skipped keys across multiple epochs.
    // In each round:
    // Alice sends 60 messages (Bob will receive only message 59, skipping 0..58 = 59 skipped keys)
    // Bob sends 1 message back to advance the DH ratchet turnaround.
    // 20 rounds * 59 skipped keys = 1,180 skipped keys accumulated.
    // Since MAX_SKIPPED_KEYS = 1000, exactly 180 oldest keys must be pruned.

    let mut saved_early_messages: Vec<Message> = Vec::new();
    let mut saved_late_messages: Vec<Message> = Vec::new();

    for round in 0..20 {
        let mut round_msgs = Vec::new();
        for i in 0..60 {
            let payload = [(round * 60 + i) as u8; 16];
            let msg = alice.encrypt_message(&payload).unwrap();
            round_msgs.push(msg);
        }

        // Save some messages from early rounds (e.g. round 0) to verify eviction
        if round == 0 {
            saved_early_messages.push(round_msgs[5].clone());
            saved_early_messages.push(round_msgs[10].clone());
        }

        // Save some messages from recent rounds (e.g. round 19) to verify they are preserved
        if round == 19 {
            saved_late_messages.push(round_msgs[5].clone());
            saved_late_messages.push(round_msgs[10].clone());
        }

        // Bob receives only message 59 (skipping 0..58)
        let dec = bob.decrypt_message(&round_msgs[59], &[round as u8; 32], &[round as u8; 64], &[round as u8; 32]).unwrap();
        assert_eq!(dec, [(round * 60 + 59) as u8; 16]);

        // Bob replies with 1 message so Alice & Bob advance the DH ratchet
        let reply = bob.encrypt_message(b"ack").unwrap();
        let dec_ack = alice.decrypt_message(&reply, &[round as u8; 32], &[round as u8; 64], &[round as u8; 32]).unwrap();
        assert_eq!(dec_ack, b"ack");
    }

    // Sub-test 1: Verify early messages whose keys were evicted fail to decrypt
    for early_msg in &saved_early_messages {
        let res = bob.decrypt_message(early_msg, &[0x99; 32], &[0x99; 64], &[0x99; 32]);
        assert!(
            res.is_err(),
            "Bob successfully decrypted a message whose skipped key should have been evicted by FIFO pruning!"
        );
    }

    // Sub-test 2: Verify late messages whose keys are within the 1000-key window decrypt successfully
    for (idx, late_msg) in saved_late_messages.iter().enumerate() {
        let res = bob.decrypt_message(late_msg, &[0x88; 32], &[0x88; 64], &[0x88; 32]);
        assert!(
            res.is_ok(),
            "Bob failed to decrypt late skipped message {} that should be present in memory!",
            idx
        );
    }
}

#[test]
fn test_skipped_key_one_time_consumption_and_replay_rejection() {
    let (mut alice, mut bob) = setup_sessions();

    let mut msgs = Vec::new();
    for i in 0..10 {
        let msg = alice.encrypt_message(&[i as u8; 32]).unwrap();
        msgs.push(msg);
    }

    // Bob receives message 5 first (skipping 0..4)
    let dec5 = bob.decrypt_message(&msgs[5], &[1; 32], &[1; 64], &[1; 32]).unwrap();
    assert_eq!(dec5, [5u8; 32]);

    // Bob receives skipped message 2
    let dec2 = bob.decrypt_message(&msgs[2], &[2; 32], &[2; 64], &[2; 32]).unwrap();
    assert_eq!(dec2, [2u8; 32]);

    // Adversary attempts replay of message 2
    let replay_res = bob.decrypt_message(&msgs[2], &[3; 32], &[3; 64], &[3; 32]);
    assert!(
        replay_res.is_err(),
        "Bob allowed replay of already-consumed skipped message key!"
    );
}
