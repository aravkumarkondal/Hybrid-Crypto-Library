use e2ee::identity::{IdentityKeyPair};
use e2ee::prekeys::{SignedPreKeyPair, OneTimePreKeyPair, PreKeyBundle};
use e2ee::session::Session;
use e2ee::errors::E2EError;

#[test]
fn test_e2ee_message_replay_attack() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32]).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);
    
    let bob_bundle = PreKeyBundle {
        identity_key: bob_identity.public_key(),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };
    
    let (mut alice_session, prekey_msg, initial_msg) = Session::setup_as_initiator(
        &alice_identity, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32]
    ).unwrap();
    
    let mut bob_session = Session::setup_as_responder(&bob_identity, &bob_spk, Some(&bob_opk), &prekey_msg).unwrap();
    
    // Bob receives the initial message
    bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    
    // Alice sends msg1
    let msg1_text = b"Hello Bob, this is Alice.";
    let msg1 = alice_session.encrypt_message(msg1_text).unwrap();
    let decrypted_pt1 = bob_session.decrypt_message(&msg1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
    assert_eq!(decrypted_pt1, msg1_text);
    
    // Attacker (Eve) captures msg1 and replays it to Bob!
    let replay_result = bob_session.decrypt_message(&msg1, &[0x81; 32], &[0x82; 64], &[0x83; 32]);
    
    // The ratchet should reject this because the message keys were already used/deleted
    assert!(replay_result.is_err(), "E2EE Ratchet MUST reject message replay attacks!");
    assert_eq!(replay_result.err().unwrap(), E2EError::MessageOutOfOrder);
}

#[test]
fn test_e2ee_forward_secrecy_compromise() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32]).unwrap();
    
    let bob_bundle = PreKeyBundle {
        identity_key: bob_identity.public_key(),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: None,
        one_time_prekey_ecc_public: None,
        one_time_prekey_pqc_public: None,
    };
    
    let (mut alice_session, prekey_msg, initial_msg) = Session::setup_as_initiator(
        &alice_identity, &bob_bundle, &[0x51; 32], &[0x52; 32], None, &[0x54; 32], &[0x55; 64], &[0x56; 32]
    ).unwrap();
    
    let mut bob_session = Session::setup_as_responder(&bob_identity, &bob_spk, None, &prekey_msg).unwrap();
    bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    
    let pt1 = b"Secret message 1";
    let msg1 = alice_session.encrypt_message(pt1).unwrap();
    bob_session.decrypt_message(&msg1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
    
    let pt2 = b"Secret message 2";
    let msg2 = alice_session.encrypt_message(pt2).unwrap();
    bob_session.decrypt_message(&msg2, &[0x81; 32], &[0x82; 64], &[0x83; 32]).unwrap();
    
    // EVE COMPROMISES BOB'S DEVICE NOW
    // Eve steals bob_session state. She wants to decrypt msg1 and msg2.
    let eve_attempt_1 = bob_session.decrypt_message(&msg2, &[0x91; 32], &[0x92; 64], &[0x93; 32]);
    assert!(eve_attempt_1.is_err(), "Forward Secrecy guarantees past messages cannot be decrypted after state compromise!");
}

#[test]
fn test_e2ee_post_compromise_security_healing() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32]).unwrap();
    
    let bob_bundle = PreKeyBundle {
        identity_key: bob_identity.public_key(),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: None,
        one_time_prekey_ecc_public: None,
        one_time_prekey_pqc_public: None,
    };
    
    let (mut alice_session, prekey_msg, initial_msg) = Session::setup_as_initiator(
        &alice_identity, &bob_bundle, &[0x51; 32], &[0x52; 32], None, &[0x54; 32], &[0x55; 64], &[0x56; 32]
    ).unwrap();
    
    let mut bob_session = Session::setup_as_responder(&bob_identity, &bob_spk, None, &prekey_msg).unwrap();
    bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    
    let msg1 = bob_session.encrypt_message(b"Hi Alice").unwrap();
    alice_session.decrypt_message(&msg1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
    
    // ALICE'S DEVICE IS COMPROMISED
    let mut attacker_session = alice_session.clone();
    
    let msg2 = bob_session.encrypt_message(b"Another message").unwrap();
    let attacker_pt = attacker_session.decrypt_message(&msg2, &[0x81; 32], &[0x82; 64], &[0x83; 32]).unwrap();
    assert_eq!(attacker_pt, b"Another message");
    
    // HEALING RATCHET
    let msg3 = alice_session.encrypt_message(b"Healing message").unwrap();
    bob_session.decrypt_message(&msg3, &[0x91; 32], &[0x92; 64], &[0x93; 32]).unwrap();
    
    let msg4 = bob_session.encrypt_message(b"Secure again").unwrap();
    
    // At this point, attacker CAN read msg4 because they have Alice's old DH key
    // The attacker attempts to update their own ratchet state using their own randomness (since they don't know Alice's future RNG outputs)
    let attacker_attempt_msg4 = attacker_session.decrypt_message(&msg4, &[0xAA; 32], &[0xAB; 64], &[0xAC; 32]);
    assert!(attacker_attempt_msg4.is_ok(), "Attacker can read msg4 because healing requires a full round trip");

    // ALICE receives msg4. This turns Alice's DH ratchet, generating a NEW DH key!
    alice_session.decrypt_message(&msg4, &[0xA1; 32], &[0xA2; 64], &[0xA3; 32]).unwrap();
    
    // Alice sends msg5 using her NEW DH key.
    let msg5 = alice_session.encrypt_message(b"Fully healed").unwrap();
    bob_session.decrypt_message(&msg5, &[0xB1; 32], &[0xB2; 64], &[0xB3; 32]).unwrap();
    
    // Bob sends msg6
    let msg6 = bob_session.encrypt_message(b"Cannot be read by attacker").unwrap();
    
    // Attacker tries to read msg6.
    // They do NOT have Alice's new DH key, so they cannot compute the shared secret!
    let attacker_attempt_msg6 = attacker_session.decrypt_message(&msg6, &[0xC1; 32], &[0xC2; 64], &[0xC3; 32]);
    assert!(attacker_attempt_msg6.is_err(), "Post-Compromise Security (PCS) MUST heal the session after a full DH ratchet turn!");
}
