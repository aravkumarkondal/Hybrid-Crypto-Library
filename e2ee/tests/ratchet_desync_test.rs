use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session};

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
fn test_ratchet_desync_vulnerability() {
    let (mut alice, mut bob) = setup_sessions();

    // Alice sends initial message after setup
    let m1 = alice.encrypt_message(b"First message").unwrap();
    let p1 = bob.decrypt_message(&m1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
    assert_eq!(p1, b"First message");

    // Alice sends second message
    let m2 = alice.encrypt_message(b"Second message with state advance").unwrap();

    // Adversary tampers with the ciphertext
    let mut tampered_m2 = m2.clone();
    tampered_m2.ciphertext[0] ^= 0xff;

    // Bob attempts to decrypt tampered message -> must fail
    let decrypt_err = bob.decrypt_message(&tampered_m2, &[0x81; 32], &[0x82; 64], &[0x83; 32]);
    assert!(decrypt_err.is_err(), "Decryption of tampered ciphertext must fail");

    // CRITICAL: Ratchet desync prevention. Because of atomic rollback,
    // Bob's state was NOT corrupted or advanced. Bob can now decrypt the untampered m2.
    let p2 = bob.decrypt_message(&m2, &[0x81; 32], &[0x82; 64], &[0x83; 32]).expect(
        "Ratchet desynchronization occurred! Failed decryption burned ratchet state or keys"
    );
    assert_eq!(p2, b"Second message with state advance");

    // Verify conversation can continue bidirectionally without error
    let bob_reply = bob.encrypt_message(b"Bob reply after recovered attack").unwrap();
    let alice_p = alice.decrypt_message(&bob_reply, &[0x91; 32], &[0x92; 64], &[0x93; 32]).unwrap();
    assert_eq!(alice_p, b"Bob reply after recovered attack");
}
