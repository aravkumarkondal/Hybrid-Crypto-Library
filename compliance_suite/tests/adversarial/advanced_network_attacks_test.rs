#[cfg(test)]
mod network_and_persistence_attacks {
    use e2ee::identity::IdentityKeyPair;
    use e2ee::prekeys::SignedPreKeyPair;
    use e2ee::session::Session;

    // 1. Session Rollback Attack (Persistence Attack)
    // An attacker has read/write access to the local disk. They backup the E2EE session database,
    // wait for Alice and Bob to exchange messages, and then overwrite Alice's database with the old backup.
    // The attacker's goal is to force Alice to reuse old keys or sequence numbers (breaking forward secrecy
    // or causing AES-GCM nonce reuse).
    // The Double Ratchet must naturally fail to decrypt incoming new messages (because it lacks the new keys),
    // and if Alice encrypts a new message, Bob will reject it because the sequence number/ratchet key
    // is stale/already used (Replay Attack defense).
    #[test]
    fn test_session_rollback_defense() {
        let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
        let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
        let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32])).unwrap();
        let bob_bundle = e2ee::prekeys::PreKeyBundle {
            identity_key: futures::executor::block_on(bob_identity.public_key()),
            signed_prekey_id: bob_spk.id,
            signed_prekey_ecc_public: bob_spk.ecc_public,
            signed_prekey_pqc_public: bob_spk.pqc_public.clone(),
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

        use e2ee::serialization::Serialize;
        // The attacker creates a backup of Alice's state at Message 0
        let alice_backup = alice_session.serialize();

        // Alice and Bob exchange messages
        let m1 = alice_session.encrypt_message(b"Msg1").unwrap();
        let _ = bob_session.decrypt_message(&m1, &[0x71; 32], &[0x72; 64], &[0x73; 32]).unwrap();
        
        let m2_bob = bob_session.encrypt_message(b"Bob Msg1", &[0x81; 32], &[0x82; 64], &[0x83; 32]).unwrap();
        let _ = alice_session.decrypt_message(&m2_bob, &[0x91; 32], &[0x92; 64], &[0x93; 32]).unwrap();

        // The attacker strikes: They delete Alice's current state and restore the backup!
        let mut alice_hacked_session = Session::deserialize(&alice_backup).unwrap();
        
        // Scenario A: Bob sends a new message to Alice.
        let m3_bob = bob_session.encrypt_message(b"Bob Msg2", &[0xA1; 32], &[0xA2; 64], &[0xA3; 32]).unwrap();
        
        // Alice attempts to decrypt it. Because she was rolled back, she is entirely desynchronized.
        // Her Ratchet chain cannot derive the key Bob used. 
        assert!(alice_hacked_session.decrypt_message(&m3_bob, &[0xB1; 32], &[0xB2; 64], &[0xB3; 32]).is_err(), 
                "Session Rollback Defense: Stale session cannot decrypt future messages (Forward Secrecy maintained!)");
                
        // Scenario B: Alice (unaware of rollback) encrypts a new message.
        // Because she was rolled back, she re-uses Message Number 1 (which she already used for `m1`).
        let m4_alice = alice_hacked_session.encrypt_message(b"Msg2").unwrap();
        
        // Bob receives it. Bob's state is at Message Number 1 for Alice's chain, but he already processed it!
        assert!(bob_session.decrypt_message(&m4_alice, &[0xC1; 32], &[0xC2; 64], &[0xC3; 32]).is_err(),
                "Session Rollback Defense: Peer MUST reject messages from a rolled-back session as replays/stale MACs!");
    }

    // 2. Session Fixation Attack (Network Attack)
    // An attacker intercepts Alice's request for Bob's PreKeyBundle and injects their *own* PreKeyBundle
    // (with known keys) pretending it's Bob's. 
    // They hope Alice will establish a session with the attacker's keys, allowing the attacker to decrypt everything.
    // Defense: Alice's protocol MUST cryptographically pin Bob's Identity Key. If the attacker substitutes
    // the bundle, they cannot forge Bob's ML-DSA signature over the PreKeyBundle.
    #[test]
    fn test_session_fixation_attack() {
        let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
        let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
        
        // Attacker generates their own keys
        let attacker_identity = IdentityKeyPair::generate(&[0x91; 32], &[0x92; 32]);
        let attacker_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x93; 32], &[0x94; 64], &attacker_identity, &[0x95; 32])).unwrap();
        
        // Attacker creates a bundle but puts Bob's Identity Key in it, hoping Alice won't notice
        // However, the signature inside the bundle was generated using the ATTACKER'S private key
        // because the attacker does not possess Bob's private key!
        let forged_bundle = e2ee::prekeys::PreKeyBundle {
            identity_key: futures::executor::block_on(bob_identity.public_key()), // Spoofed Bob Identity
            signed_prekey_id: attacker_spk.id,
            signed_prekey_ecc_public: attacker_spk.ecc_public,
            signed_prekey_pqc_public: attacker_spk.pqc_public.clone(),
            signed_prekey_signature: attacker_spk.signature.clone(), // This signature is INVALID for Bob's Public Key!
            one_time_prekey_id: None,
            one_time_prekey_ecc_public: None,
            one_time_prekey_pqc_public: None,
        };

        // Alice tries to initiate a session. The E2EE protocol MUST cryptographically verify
        // that the signature in the bundle is valid for the `identity_key` provided.
        // Since `identity_key` is Bob, but `signature` is from the Attacker, it MUST fail!
        let result = Session::setup_as_initiator(
            &alice_identity, &forged_bundle, &[0x51; 32], &[0x52; 32], None, &[0x54; 32], &[0x55; 64], &[0x56; 32]
        );
        
        assert!(result.is_err(), "Session Fixation Defense: Protocol MUST abort when Signature fails to validate against the pinned Identity!");
    }
}
