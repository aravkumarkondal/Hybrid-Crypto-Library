use e2ee::{IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair, PreKeyBundle, Session};
extern crate alloc;
use alloc::vec::Vec;

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
fn test_ratchet_excessive_skipped_keys() {
    let (mut alice, mut bob) = setup_sessions();
    
    let mut messages = Vec::new();
    for i in 0..105 {
        messages.push(alice.encrypt_message(format!("Msg {}", i).as_bytes()).unwrap());
    }
    
    // Simulate Bob skipping over 101 messages (the hard limit is +100 inside skip_message_keys)
    let res = bob.decrypt_message(&messages[102], &[0x99; 32], &[0x99; 64], &[0x99; 32]);
    assert!(res.is_err(), "Should reject skipping more than 100 messages at once");
    
    // If we skip in chunks of 50, we bypass the single-skip limit and test MAX_SKIPPED_KEYS eviction (MAX = 1000)
    let (mut alice2, mut bob2) = setup_sessions();
    
    let mut more_messages = Vec::new();
    for i in 0..1050 {
        more_messages.push(alice2.encrypt_message(format!("Msg {}", i).as_bytes()).unwrap());
    }
    
    for i in 1..21 {
        // Skip 50 at a time
        bob2.decrypt_message(&more_messages[i * 50], &[0x99; 32], &[0x99; 64], &[0x99; 32]).unwrap();
    }
    
    assert_eq!(e2ee::SessionState::deserialize_secure(&bob2.export_state(&[0u8; 32]), &[0u8; 32]).unwrap().ratchet.skipped_message_keys.len(), 981);
}
