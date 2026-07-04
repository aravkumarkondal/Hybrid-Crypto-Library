use proptest::prelude::*;
use proptest::collection::vec;
use e2ee::identity::{IdentityKeyPair, IdentityPublicKey};
use e2ee::messages::{Message, MessageHeader};
use e2ee::serialization::Serialize;
use e2ee::sender_keys::{SenderKeyContext, SenderKeyReceiver, SenderKeyMessage};

prop_compose! {
    fn arb_identity_public_key()(
        ecc_public in any::<[u8; 32]>(),
        pqc_public in vec(any::<u8>(), 0..2000)
    ) -> IdentityPublicKey {
        IdentityPublicKey {
            ecc_public,
            pqc_public,
        }
    }
}

prop_compose! {
    fn arb_message_header()(
        dh_public in any::<[u8; 32]>(),
        kem_public in any::<[u8; 1184]>(),
        kem_ciphertext in any::<[u8; 1088]>(),
        previous_chain_length in any::<u32>(),
        message_number in any::<u32>(),
    ) -> MessageHeader {
        MessageHeader {
            dh_public,
            kem_public,
            kem_ciphertext,
            previous_chain_length,
            message_number,
        }
    }
}

prop_compose! {
    fn arb_message()(
        header in arb_message_header(),
        ciphertext in vec(any::<u8>(), 0..1000),
        auth_tag in any::<[u8; 16]>(),
    ) -> Message {
        Message {
            header,
            ciphertext,
            auth_tag,
        }
    }
}

proptest! {
    #[test]
    fn test_identity_public_key_serialization_roundtrip(key in arb_identity_public_key()) {
        let serialized = key.serialize();
        let deserialized = IdentityPublicKey::deserialize(&serialized).unwrap();
        assert_eq!(key.ecc_public, deserialized.ecc_public);
        assert_eq!(key.pqc_public, deserialized.pqc_public);
    }

    #[test]
    fn test_message_serialization_roundtrip(msg in arb_message()) {
        let serialized = msg.serialize();
        let deserialized = Message::deserialize(&serialized).unwrap();
        
        assert_eq!(msg.header.dh_public, deserialized.header.dh_public);
        assert_eq!(msg.header.kem_public[..], deserialized.header.kem_public[..]);
        assert_eq!(msg.header.kem_ciphertext[..], deserialized.header.kem_ciphertext[..]);
        assert_eq!(msg.header.previous_chain_length, deserialized.header.previous_chain_length);
        assert_eq!(msg.header.message_number, deserialized.header.message_number);
        
        assert_eq!(msg.ciphertext, deserialized.ciphertext);
        assert_eq!(msg.auth_tag, deserialized.auth_tag);
    }

    #[test]
    fn test_sender_key_deserialization_no_crash(payload in vec(any::<u8>(), 0..10000)) {
        // Just ensure it doesn't panic
        let _ = SenderKeyMessage::deserialize(&payload);
    }
    
    #[test]
    fn test_ratchet_advancing_invariants(gap in 0u32..5u32, plaintext in vec(any::<u8>(), 1..100)) {
        let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
        let group_id = [9; 32];
        let seed = [10; 32];
        
        let mut context = SenderKeyContext::new(alice_identity, &group_id, &seed, 1);
        let dist_msg = context.get_distribution_message();
        let mut receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);
        
        // Advance the context by `gap` messages
        for _ in 0..gap {
            let _ = context.chain.next_message_key();
        }
        
        // Encrypt the actual message
        let msg = context.encrypt(&plaintext).unwrap();
        
        // Receiver should decrypt it correctly, skipping the gap
        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
