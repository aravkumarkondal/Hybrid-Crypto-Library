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
    let plaintext = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    assert_eq!(plaintext, b"");

    (alice_session, bob_session)
}

#[test]
fn test_ratchet_in_order() {
    let (mut alice, mut bob) = setup_sessions();
    for i in 0..10 {
        let text = format!("Message {}", i);
        let msg = alice.encrypt_message(text.as_bytes()).unwrap();
        let dec = bob.decrypt_message(&msg, &[i; 32], &[i; 64], &[i; 32]).unwrap();
        assert_eq!(dec, text.as_bytes());
    }
}

#[test]
fn test_ratchet_out_of_order() {
    let (mut alice, mut bob) = setup_sessions();
    let m1 = alice.encrypt_message(b"M1").unwrap();
    let m2 = alice.encrypt_message(b"M2").unwrap();
    let m3 = alice.encrypt_message(b"M3").unwrap();

    assert_eq!(bob.decrypt_message(&m3, &[3;32], &[3;64], &[3;32]).unwrap(), b"M3");
    assert_eq!(bob.decrypt_message(&m1, &[1;32], &[1;64], &[1;32]).unwrap(), b"M1");
    assert_eq!(bob.decrypt_message(&m2, &[2;32], &[2;64], &[2;32]).unwrap(), b"M2");
}

#[test]
fn test_ratchet_message_loss() {
    let (mut alice, mut bob) = setup_sessions();
    let _m1 = alice.encrypt_message(b"M1").unwrap(); // Lost
    let m2 = alice.encrypt_message(b"M2").unwrap();

    assert_eq!(bob.decrypt_message(&m2, &[2;32], &[2;64], &[2;32]).unwrap(), b"M2");
}

#[test]
fn test_ratchet_duplicates() {
    let (mut alice, mut bob) = setup_sessions();
    let m1 = alice.encrypt_message(b"M1").unwrap();

    assert_eq!(bob.decrypt_message(&m1, &[1;32], &[1;64], &[1;32]).unwrap(), b"M1");
    assert!(bob.decrypt_message(&m1, &[1;32], &[1;64], &[1;32]).is_err());
}

#[test]
fn test_ratchet_huge_gaps_and_massive_skipped_key_recovery() {
    let (mut alice, mut bob) = setup_sessions();
    
    // Alice sends 50 messages
    let mut messages = Vec::new();
    for i in 0..50 {
        messages.push(alice.encrypt_message(format!("Msg {}", i).as_bytes()).unwrap());
    }

    // Bob receives the 49th message first
    let dec = bob.decrypt_message(&messages[49], &[0x99; 32], &[0x99; 64], &[0x99; 32]).unwrap();
    assert_eq!(dec, b"Msg 49");

    // Recover some massive skipped keys
    assert_eq!(bob.decrypt_message(&messages[30], &[0x99; 32], &[0x99; 64], &[0x99; 32]).unwrap(), b"Msg 30");
    assert_eq!(bob.decrypt_message(&messages[10], &[0x99; 32], &[0x99; 64], &[0x99; 32]).unwrap(), b"Msg 10");
}
