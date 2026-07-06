extern crate alloc;
use e2ee::{MessagePayload, Attachment, Message, MessageHeader, E2EError};

#[test]
fn test_payload_serialization_roundtrip() {
    let mut payload = MessagePayload::new(b"Hello World");
    payload.expires_at = Some(1600000000);
    
    let att = Attachment {
        attachment_id: [1; 16],
        aes_key: [2; 32],
        iv: [3; 12],
        sha256_hash: [4; 32],
    };
    payload.attachments.push(att.clone());

    let serialized = payload.serialize(None);
    
    let deserialized = MessagePayload::deserialize(&serialized).expect("Deserialization failed");
    
    assert_eq!(deserialized.body, b"Hello World");
    assert_eq!(deserialized.expires_at, Some(1600000000));
    assert_eq!(deserialized.attachments.len(), 1);
    assert_eq!(deserialized.attachments[0], att);
}

#[test]
fn test_payload_padding() {
    let payload = MessagePayload::new(b"Short message");
    
    // Serialize with 256-byte block padding
    let serialized = payload.serialize(Some(256));
    
    // The length should be exactly a multiple of 256
    assert_eq!(serialized.len() % 256, 0);
    
    // Deserialization should seamlessly ignore the TYPE_PADDING and recover the message
    let deserialized = MessagePayload::deserialize(&serialized).expect("Deserialization failed");
    assert_eq!(deserialized.body, b"Short message");
    assert_eq!(deserialized.expires_at, None);
    assert!(deserialized.attachments.is_empty());
}

#[test]
fn test_payload_expiration_check() {
    let mut payload = MessagePayload::new(b"Self-destructing message");
    payload.expires_at = Some(1000); // Expires at timestamp 1000
    
    let serialized = payload.serialize(None);
    
    let key = [0u8; 32];
    let iv = [0u8; 12];
    let header = MessageHeader {
        dh_public: [0; 32],
        kem_public: [0; 1184],
        kem_ciphertext: [0; 1088],
        previous_chain_length: 0,
        message_number: 1,
    };
    
    let msg = Message::encrypt(&key, &iv, header, &serialized);
    
    // Decrypt at timestamp 999 (Valid)
    let dec_valid = msg.decrypt_payload(&key, &iv, 999);
    assert!(dec_valid.is_ok());
    
    // Decrypt at timestamp 1000 (Expired)
    let dec_expired = msg.decrypt_payload(&key, &iv, 1000);
    assert!(matches!(dec_expired, Err(E2EError::MessageExpired)));
    
    // Decrypt at timestamp 2000 (Expired)
    let dec_expired2 = msg.decrypt_payload(&key, &iv, 2000);
    assert!(matches!(dec_expired2, Err(E2EError::MessageExpired)));
}
