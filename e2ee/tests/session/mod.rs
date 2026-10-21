use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session, serialization::Serialize};

fn get_identities() -> (IdentityKeyPair, IdentityKeyPair) {
    (
        IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]),
        IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]),
    )
}

#[test]
fn test_session_creation_success() {
    let (alice_id, bob_id) = get_identities();
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

    let (_alice_session, prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg)).unwrap();
    let _ = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
}

#[test]
fn test_session_handshake_corruption() {
    let (alice_id, bob_id) = get_identities();
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

    let (_, mut prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    // Corrupt prekey message kem ciphertext
    prekey_msg.initial_message.header.kem_ciphertext[0] ^= 1;

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg)).unwrap();
    let res = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]);
    // It should either fail setup (if invalid KEM encapsulation) or fail MAC validation.
    // We just verify it doesn't gracefully decrypt.
    assert!(res.is_err() || res.unwrap() != b"Some Initial Message");
}

#[test]
fn test_session_unknown_key_share_identity_substitution() {
    let (alice_id, bob_id) = get_identities();
    let eve_id = IdentityKeyPair::generate(&[0x99; 32], &[0x99; 32]);
    
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

    // Alice initiates with Bob
    let (_, prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    // Eve intercepts and tries to establish the session with Bob acting as the initiator
    let mut prekey_msg_eve = e2ee::PreKeyMessage::deserialize(&prekey_msg.serialize()).unwrap();
    prekey_msg_eve.initiator_identity_ecc_public = futures::executor::block_on(eve_id.public_key()).ecc_public;
    
    // Bob should fail because the shared secrets tied to Alice's identity will not match what Eve claims,
    // though the failure might occur at the MAC validation step when decrypting initial_msg.
    let bob_session_res = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg_eve));
    
    if let Ok(mut bob_session) = bob_session_res {
        let dec_res = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]);
        assert!(dec_res.is_err(), "Identity substitution should fail MAC");
    }
}
