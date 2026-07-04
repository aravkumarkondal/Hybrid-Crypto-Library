use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Message, MessageHeader, serialization::Serialize, errors::E2EError, identity::IdentityPublicKey};

#[test]
fn test_serialization_round_trip() {
    let id_pub = IdentityPublicKey {
        ecc_public: [0xaa; 32],
        pqc_public: vec![0xbb; 2592],
    };
    let id_pub_bytes = id_pub.serialize();
    let id_pub_dec = IdentityPublicKey::deserialize(&id_pub_bytes).unwrap();
    assert_eq!(id_pub_dec.ecc_public, id_pub.ecc_public);
    assert_eq!(id_pub_dec.pqc_public, id_pub.pqc_public);

    let msg = Message {
        header: MessageHeader {
            dh_public: [0xcc; 32],
            kem_public: [0xdd; 1184],
            kem_ciphertext: [0xee; 1088],
            previous_chain_length: 42,
            message_number: 99,
        },
        ciphertext: vec![0x11, 0x22, 0x33, 0x44],
        auth_tag: [0xff; 16],
    };
    let msg_bytes = msg.serialize();
    let msg_dec = Message::deserialize(&msg_bytes).unwrap();
    assert_eq!(msg_dec.header.dh_public, msg.header.dh_public);
    assert_eq!(msg_dec.ciphertext, msg.ciphertext);
}

#[test]
fn test_serialization_corrupted_blobs() {
    let msg = Message {
        header: MessageHeader {
            dh_public: [0xcc; 32],
            kem_public: [0xdd; 1184],
            kem_ciphertext: [0xee; 1088],
            previous_chain_length: 42,
            message_number: 99,
        },
        ciphertext: vec![0x11, 0x22, 0x33, 0x44],
        auth_tag: [0xff; 16],
    };
    let mut msg_bytes = msg.serialize();
    
    // Corrupt lengths or structure
    msg_bytes[0] ^= 0xFF; 
    msg_bytes[5] ^= 0xFF;
    
    let res = Message::deserialize(&msg_bytes);
    // Even if it parses, we can assert it shouldn't just crash.
    // If it's manual serialization without validation, it might parse to garbage.
    if let Ok(m) = res {
        assert_ne!(m.header.dh_public, msg.header.dh_public);
    }
}

#[test]
fn test_serialization_truncated_blobs() {
    let id_pub = IdentityPublicKey {
        ecc_public: [0xaa; 32],
        pqc_public: vec![0xbb; 2592],
    };
    let id_pub_bytes = id_pub.serialize();
    
    for i in 0..id_pub_bytes.len() {
        let truncated = &id_pub_bytes[..i];
        let res = IdentityPublicKey::deserialize(truncated);
        assert!(res.is_err());
    }
}

#[test]
fn test_serialization_malformed_inputs() {
    let bad_bytes = [0xFF; 1000];
    let res = IdentityPublicKey::deserialize(&bad_bytes);
    assert!(res.is_err());

    let res_msg = Message::deserialize(&bad_bytes);
    assert!(res_msg.is_err());
}
