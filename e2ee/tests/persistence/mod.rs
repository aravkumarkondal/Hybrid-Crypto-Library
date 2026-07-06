use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session, serialization::Serialize};

fn setup_sessions() -> (Session, Session) {
    let alice_id = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_id = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_id, &[0x33; 32]).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);
    
    let bob_bundle = PreKeyBundle {
        identity_key: bob_id.public_key(),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };

    let (alice_session, prekey_msg, initial_msg) = Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    ).unwrap();

    let mut bob_session = Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg).unwrap();
    let _ = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();

    (alice_session, bob_session)
}

#[test]
fn test_persistence_save_restore_during_ratchet() {
    let (mut alice, mut bob) = setup_sessions();
    let m1 = alice.encrypt_message(b"Hello before save").unwrap();
    let dec1 = bob.decrypt_message(&m1, &[1;32], &[1;64], &[1;32]).unwrap();
    assert_eq!(dec1, b"Hello before save");

    let bob_state_bytes = bob.export().serialize();

    // Restore bob's session
    let mut bob_restored = Session::restore(&e2ee::SessionState::deserialize(&bob_state_bytes).unwrap());

    // Alice continues encrypting
    let m2 = alice.encrypt_message(b"Hello after restore").unwrap();
    
    // Restored bob should be able to decrypt
    let dec2 = bob_restored.decrypt_message(&m2, &[2;32], &[2;64], &[2;32]).unwrap();
    assert_eq!(dec2, b"Hello after restore");
}

#[test]
fn test_persistence_corrupted_state() {
    let (_alice, bob) = setup_sessions();
    let mut bob_state_bytes = bob.export().serialize();

    // Corrupt byte 100
    if bob_state_bytes.len() > 100 {
        bob_state_bytes[100] ^= 0x55;
    }
    
    // Exact state recovery fails gracefully
    let restored = e2ee::SessionState::deserialize(&bob_state_bytes);
    assert!(restored.is_err());
}
