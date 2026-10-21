use e2ee::identity::IdentityKeyPair;
use e2ee::prekeys::{SignedPreKeyPair, PreKeyBundle};
use e2ee::session::Session;
use e2ee::errors::E2EError;

#[test]
fn test_e2ee_ratchet_dos_protection() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32])).unwrap();
    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_identity.public_key()),
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
    
    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_identity, &bob_spk, None, &prekey_msg)).unwrap();
    bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    
    // Attacker intercepts Alice's next message and maliciously modifies the message sequence number to 10,000
    // This forces the receiver to derive 10,000 keys, causing a CPU/Memory exhaustion DoS.
    let mut malicious_msg = alice_session.encrypt_message(b"Hi Bob").unwrap();
    malicious_msg.header.message_number = 10_000; 
    
    let result = bob_session.decrypt_message(&malicious_msg, &[0x71; 32], &[0x72; 64], &[0x73; 32]);
    
    // The ratchet MUST abort with an error rather than attempting to skip 10,000 keys
    assert!(result.is_err(), "Ratchet MUST protect against DoS attacks by rejecting excessive skipped messages");
    assert_eq!(result.err().unwrap(), E2EError::DoubleRatchetError);
}

#[test]
fn test_e2ee_extreme_message_dropping() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32])).unwrap();
    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_identity.public_key()),
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
    
    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_identity, &bob_spk, None, &prekey_msg)).unwrap();
    bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();
    
    // Alice sends 5 messages
    let msg1 = alice_session.encrypt_message(b"Msg 1").unwrap();
    let msg2 = alice_session.encrypt_message(b"Msg 2").unwrap();
    let msg3 = alice_session.encrypt_message(b"Msg 3").unwrap();
    let msg4 = alice_session.encrypt_message(b"Msg 4").unwrap();
    let msg5 = alice_session.encrypt_message(b"Msg 5").unwrap();
    
    // Bob receives msg 1, 3, and 5 (extreme packet dropping)
    bob_session.decrypt_message(&msg1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
    bob_session.decrypt_message(&msg3, &[0x81; 32], &[0x82; 64], &[0x83; 32]).unwrap();
    bob_session.decrypt_message(&msg5, &[0x91; 32], &[0x92; 64], &[0x93; 32]).unwrap();
    
    // Now Bob receives the out-of-order delayed messages!
    let dec_msg2 = bob_session.decrypt_message(&msg2, &[0xA1; 32], &[0xA2; 64], &[0xA3; 32]).unwrap();
    assert_eq!(dec_msg2, b"Msg 2");
    
    let dec_msg4 = bob_session.decrypt_message(&msg4, &[0xB1; 32], &[0xB2; 64], &[0xB3; 32]).unwrap();
    assert_eq!(dec_msg4, b"Msg 4");
}

#[test]
fn test_e2ee_hybrid_downgrade_attack() {
    let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32])).unwrap();
    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_identity.public_key()),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: None,
        one_time_prekey_ecc_public: None,
        one_time_prekey_pqc_public: None,
    };
    
    let (_, mut prekey_msg, initial_msg) = Session::setup_as_initiator(
        &alice_identity, &bob_bundle, &[0x51; 32], &[0x52; 32], None, &[0x54; 32], &[0x55; 64], &[0x56; 32]
    ).unwrap();
    
    // Attacker intercepts PreKeyMessage and strips the Kyber encapsulation out, attempting to downgrade security to ECC-only
    prekey_msg.pqc_ciphertext_spk = [0u8; 1088]; 
    
    // Depending on the implementation, the responder should fail when trying to decapsulate an all-zero ciphertext,
    // or fail to set up entirely.
    let setup_result = Session::setup_as_responder(&bob_identity, &bob_spk, None, &prekey_msg);
    assert!(setup_result.is_ok()); // Setup might succeed with a corrupted root key due to implicit rejection.
    let mut malicious_bob = setup_result.unwrap();
    
    // Malicious bob tries to process Alice's true initial message. It MUST fail because the root keys mismatched due to PQC downgrade!
    let decrypt_result = malicious_bob.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]);
    assert!(decrypt_result.is_err(), "E2EE MUST reject hybrid downgrade attacks via MAC validation failure");
}
