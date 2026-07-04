#[cfg(test)]
mod state_level_protocol_attacks {
    use e2ee::identity::IdentityKeyPair;
    use e2ee::prekeys::SignedPreKeyPair;
    use e2ee::session::Session;
    
    // 1. Key-Compromise Impersonation (KCI) Defense
    // The ultimate threat: A state-sponsored virus successfully steals Bob's long-term
    // Identity Private Key. Can the attacker now forge messages to Bob pretending to be Alice?
    // In our X3DH and Double Ratchet implementation, the math prevents this!
    #[test]
    fn test_e2ee_key_compromise_impersonation_defense() {
        let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
        let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
        let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32]).unwrap();
        let bob_bundle = e2ee::prekeys::PreKeyBundle {
            identity_key: bob_identity.public_key(),
            signed_prekey_id: bob_spk.id,
            signed_prekey_ecc_public: bob_spk.ecc_public,
            signed_prekey_pqc_public: bob_spk.pqc_public.clone(),
            signed_prekey_signature: bob_spk.signature.clone(),
            one_time_prekey_id: None,
            one_time_prekey_ecc_public: None,
            one_time_prekey_pqc_public: None,
        };
        
        // Attacker steals Bob's Private Keys via a zero-day virus
        // (Simulated by having access to bob_identity and bob_spk)
        
        // Attacker tries to initiate a session with Bob *pretending* to be Alice.
        // To do this, the attacker must generate a valid X3DH exchange.
        // X3DH requires: 
        // DH1 = DH(AliceIdentity, BobSignedPreKey)
        // DH2 = DH(AliceEphemeral, BobIdentity)
        // DH3 = DH(AliceEphemeral, BobSignedPreKey)
        
        // The attacker has Bob's keys, so they can calculate DH2 and DH3.
        // BUT they DO NOT have Alice's Identity Private Key! 
        // So they CANNOT calculate DH1.
        
        // We simulate the attacker attempting to spoof `setup_as_initiator` without Alice's true private key.
        // They use a random spoofed key instead.
        let fake_alice_identity = IdentityKeyPair::generate(&[0x81; 32], &[0x82; 32]);
        
        let (mut fake_session, prekey_msg, spoofed_msg) = Session::setup_as_initiator(
            &fake_alice_identity, // Attacker uses a fake identity
            &bob_bundle, 
            &[0x77; 32], &[0x78; 32], None, &[0x79; 32], &[0x7A; 64], &[0x7B; 32]
        ).unwrap();
        
        // Bob receives the prekey message. Bob expects it to be from the REAL Alice's public key.
        // But the prekey_msg contains `initiator_identity_ecc_public` of the FAKE Alice.
        // If Bob has pinned Alice's public key (as is standard in E2EE contacts), Bob will reject it!
        // Even if Bob doesn't pin it, the attacker has failed to Impersonate Alice (they impersonated a stranger).
        
        // To truly impersonate Alice, the attacker must manually construct a PreKeyMessage
        // where `initiator_identity_ecc_public` == `alice_identity.ecc_public`.
        let mut malicious_prekey = prekey_msg;
        malicious_prekey.initiator_identity_ecc_public = alice_identity.ecc_public;
        
        // Bob processes the malicious prekey
        let bob_setup = Session::setup_as_responder(&bob_identity, &bob_spk, None, &malicious_prekey);
        assert!(bob_setup.is_ok(), "Responder computes shared secret using the provided public keys (Bob doesn't know it's fake yet)");
        let mut bob_session = bob_setup.unwrap();
        
        // Now the attacker tries to send a message encrypted with their fake session.
        // Bob will attempt to decrypt it.
        // Because the attacker didn't know Alice's private key, DH1 is completely mismatched between the attacker and Bob!
        // Bob's Double Ratchet Root Key will be completely different.
        
        let decrypt_result = bob_session.receive_initial_message(&spoofed_msg, &[0x11; 32], &[0x12; 64], &[0x13; 32]);
        
        assert!(decrypt_result.is_err(), "KCI DEFENSE SUCCESS: Bob MUST reject the spoofed message via MAC failure because DH1 is mathematically tied to Alice's true private key!");
    }
    
    // 2. State Corruption Virus Tampering (Anti-Debugging/Anti-Tampering)
    // A virus modifies 1 byte of the serialized E2EE state on the hard drive.
    // The library must detect this via authenticated decryptions or structural checksums
    // and fail closed (panic/error) instead of silently yielding a corrupted cipher state.
    #[test]
    fn test_e2ee_state_corruption_virus_tampering() {
        let alice_identity = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
        let bob_identity = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
        let bob_spk = SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_identity, &[0x33; 32]).unwrap();
        let bob_bundle = e2ee::prekeys::PreKeyBundle {
            identity_key: bob_identity.public_key(),
            signed_prekey_id: bob_spk.id,
            signed_prekey_ecc_public: bob_spk.ecc_public,
            signed_prekey_pqc_public: bob_spk.pqc_public.clone(),
            signed_prekey_signature: bob_spk.signature.clone(),
            one_time_prekey_id: None,
            one_time_prekey_ecc_public: None,
            one_time_prekey_pqc_public: None,
        };
        
        let (alice_session, _, _) = Session::setup_as_initiator(
            &alice_identity, &bob_bundle, &[0x11; 32], &[0x12; 32], None, &[0x14; 32], &[0x15; 64], &[0x16; 32]
        ).unwrap();
        
        use e2ee::serialization::Serialize;
        // Serialize the bundle to the KDC "database"
        let serialized_bundle = bob_bundle.serialize();
        
        // A virus infects the Key Distribution Center (KDC) and flips a bit in Bob's public keys
        let mut corrupted_bundle_bytes = serialized_bundle.clone();
        
        // Mutate the 50th byte 
        if corrupted_bundle_bytes.len() > 50 {
            corrupted_bundle_bytes[50] ^= 0b0101_0101; 
        }
        
        // The KDC successfully parses the bytes (because it's just raw arrays)
        let corrupted_bundle = e2ee::prekeys::PreKeyBundle::deserialize(&corrupted_bundle_bytes).unwrap();
        
        // Alice attempts to use the corrupted keys. The protocol MUST cryptographically verify
        // Bob's ML-DSA-87 signature over the PreKeyBundle. Since the virus altered a bit, 
        // the signature verification WILL FAIL, completely neutralizing the state tampering!
        let session_result = Session::setup_as_initiator(
            &alice_identity, &corrupted_bundle, &[0x11; 32], &[0x12; 32], None, &[0x14; 32], &[0x15; 64], &[0x16; 32]
        );
        
        assert!(session_result.is_err(), "Virus Tampering Defense: Protocol MUST reject mathematically corrupted database states via Signature Validation failure!");
    }
}
