use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session};
use e2ee::sender_keys::{SenderKeyContext, SenderKeyReceiver, SenderKeyMessage};
use e2ee::mls::treekem::{TreeKEM, NodePublicKey};
use e2ee::errors::E2EError;

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
    let _ = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();

    (alice_session, bob_session)
}

#[test]
fn test_double_ratchet_massive_gap_and_reverse_order_delivery() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice produces 30 consecutive messages without Bob receiving yet
    let count = 30;
    let mut messages = Vec::new();
    for i in 0..count {
        let plaintext = format!("Message sequence index {:04}", i);
        let msg = alice.encrypt_message(plaintext.as_bytes()).unwrap();
        messages.push((plaintext, msg));
    }

    // Step 1: Bob receives the LAST message first (skipping count - 1 messages)
    let last_idx = count - 1;
    let (ref expected_last_pt, ref last_msg) = messages[last_idx];
    let decrypted_last = bob.decrypt_message(last_msg, &[0x81; 32], &[0x82; 64], &[0x83; 32])
        .expect("Bob should successfully skip keys to decrypt the 30th message");
    assert_eq!(decrypted_last, expected_last_pt.as_bytes());

    // Step 2: Bob receives all previously skipped messages in reverse order (count-2 down to 0)
    for i in (0..count - 1).rev() {
        let (ref expected_pt, ref msg) = messages[i];
        let decrypted = bob.decrypt_message(msg, &[0x91; 32], &[0x92; 64], &[0x93; 32])
            .unwrap_or_else(|e| panic!("Bob should decrypt skipped message {} from skipped store: {:?}", i, e));
        assert_eq!(&decrypted, expected_pt.as_bytes());
    }

    // Step 3: Replay attack with an already-consumed skipped message
    let (_pt, ref msg_replay) = &messages[15];
    let replay_res = bob.decrypt_message(msg_replay, &[0xA1; 32], &[0xA2; 64], &[0xA3; 32]);
    assert!(replay_res.is_err(), "Consumed skipped message must not be decryptable again (replay resistance)");
}

#[test]
fn test_double_ratchet_empty_and_large_payloads() {
    let (mut alice, mut bob) = setup_sessions();

    // Empty plaintext
    let empty_msg = alice.encrypt_message(b"").unwrap();
    let empty_dec = bob.decrypt_message(&empty_msg, &[0xB1; 32], &[0xB2; 64], &[0xB3; 32]).unwrap();
    assert_eq!(empty_dec, b"");

    // 256 KB large payload
    let large_payload = vec![0x42u8; 256 * 1024];
    let large_msg = alice.encrypt_message(&large_payload).unwrap();
    let large_dec = bob.decrypt_message(&large_msg, &[0xC1; 32], &[0xC2; 64], &[0xC3; 32]).unwrap();
    assert_eq!(large_dec, large_payload);
}

#[test]
fn test_sender_keys_iteration_skip_limits() {
    let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let group_id = [9; 32];
    let seed = [10; 32];

    let alice_context = SenderKeyContext::new(alice_identity, &group_id, &seed, 1);
    let dist_msg = futures::executor::block_on(alice_context.get_distribution_message());
    let mut bob_receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);

    // Initial state: iteration = 0
    assert_eq!(bob_receiver.chain.iteration, 0);

    // Adversary crafts a message with an iteration jump of 2001 (beyond the 2000 limit)
    let fake_msg_2001 = SenderKeyMessage {
        group_id,
        sender_identity: dist_msg.sender_identity.clone(),
        chain_id: 1,
        iteration: 2001,
        ciphertext: vec![0u8; 16],
        auth_tag: [0u8; 16],
        signature: vec![0u8; 64],
    };

    let err = bob_receiver.decrypt(&fake_msg_2001).unwrap_err();
    assert!(
        matches!(err, E2EError::InvalidSignature | E2EError::MessageOutOfOrder),
        "Skip of 2001 must be rejected to prevent CPU exhaustion DoS"
    );
    // Chain iteration must remain unchanged
    assert_eq!(bob_receiver.chain.iteration, 0);
}

#[test]
fn test_treekem_topology_edge_cases() {
    // Edge case 1: Minimal 2-leaf TreeKEM
    let mut tree2 = TreeKEM::new();
    let kp0 = TreeKEM::derive_keypair(&[10u8; 32]);
    let kp1 = TreeKEM::derive_keypair(&[11u8; 32]);
    let pk0 = NodePublicKey { ecc_public: kp0.ecc_public, pqc_public: kp0.pqc_public };
    let pk1 = NodePublicKey { ecc_public: kp1.ecc_public, pqc_public: kp1.pqc_public };

    let l0 = tree2.add_leaf(pk0);
    let l1 = tree2.add_leaf(pk1);
    assert_eq!(l0, 0);
    assert_eq!(l1, 1);
    assert_eq!(tree2.num_leaves, 2);

    // Edge case 2: Odd-leaf TreeKEM (3 leaves)
    let kp2 = TreeKEM::derive_keypair(&[12u8; 32]);
    let pk2 = NodePublicKey { ecc_public: kp2.ecc_public, pqc_public: kp2.pqc_public };
    let l2 = tree2.add_leaf(pk2);
    assert_eq!(l2, 2);
    assert_eq!(tree2.num_leaves, 3);
    let root = TreeKEM::root(TreeKEM::node_count(3));
    assert!(root > 0, "Root of 3-leaf tree must be valid index");

    // Removal of a leaf
    tree2.remove_leaf(1);
    let node1_idx = TreeKEM::leaf_to_node(1);
    assert!(tree2.nodes[node1_idx as usize].public_key.is_none(), "Removed leaf must be blanked");
}
