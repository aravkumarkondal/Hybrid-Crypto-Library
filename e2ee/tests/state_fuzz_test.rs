extern crate alloc;

use e2ee::state::{DoubleRatchetState, SessionState, SkippedKeyState};
use e2ee::serialization::Serialize;

fn create_valid_state() -> SessionState {
    let ratchet = DoubleRatchetState {
        root_key: [1; 32],
        dh_send_private: [2; 32],
        dh_send_public: [3; 32],
        dh_recv_public: Some([4; 32]),
        kem_send_private: [5; 2400],
        kem_send_public: [6; 1184],
        kem_recv_public: Some([7; 1184]),
        send_chain_key: Some([8; 32]),
        recv_chain_key: Some([9; 32]),
        send_msg_num: 10,
        recv_msg_num: 11,
        prev_send_msg_num: 12,
        skipped_message_keys: alloc::vec![
            SkippedKeyState {
                peer_dh_public: [13; 32],
                message_number: 14,
                key: [15; 32],
                iv: [16; 12],
            }
        ],
        past_dh_recv_publics: alloc::vec![[17; 32]],
    };

    SessionState::new(ratchet, Some([18; 1088]))
}

#[test]
fn test_state_fuzzing_truncations() {
    let state = create_valid_state();
    let valid_bytes = state.serialize();
    
    // Test every possible truncation
    for len in 0..valid_bytes.len() {
        let truncated = &valid_bytes[..len];
        let res = SessionState::deserialize(truncated);
        assert!(res.is_err(), "Deserialization should fail for length {}", len);
    }
}

#[test]
fn test_state_fuzzing_corruptions() {
    let state = create_valid_state();
    let valid_bytes = state.serialize();
    
    // Corrupt one byte at a time
    for i in 0..valid_bytes.len() {
        let mut corrupted = valid_bytes.clone();
        corrupted[i] ^= 0xFF; // Flip all bits in the byte
        
        let res = SessionState::deserialize(&corrupted);
        assert!(res.is_err(), "Deserialization should fail when byte {} is corrupted", i);
    }
}

#[test]
fn test_state_fuzzing_invalid_version() {
    let state = create_valid_state();
    let mut bytes = state.serialize();
    
    // Version is at offset 0, it's 4 bytes
    bytes[0] ^= 0x02; // Change version
    
    // We must re-compute the SHA256 checksum so it passes the checksum test
    // but fails the version check
    use hybrid_crypto::sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(&bytes[..bytes.len() - 32]);
    let checksum = hasher.finalize();
    
    let len = bytes.len();
    bytes[len - 32..].copy_from_slice(&checksum);
    
    let res = SessionState::deserialize(&bytes);
    assert!(res.is_err());
}

#[test]
fn test_state_fuzzing_excessive_skipped_keys() {
    let mut state = create_valid_state();
    
    // Add 2001 skipped keys
    for i in 0..2001 {
        state.ratchet.skipped_message_keys.push(SkippedKeyState {
            peer_dh_public: [0; 32],
            message_number: i,
            key: [0; 32],
            iv: [0; 12],
        });
    }
    
    let bytes = state.serialize();
    let res = SessionState::deserialize(&bytes);
    assert!(res.is_err(), "Should reject states with > 2000 skipped keys");
}

#[test]
fn test_state_fuzzing_excessive_past_dhs() {
    let mut state = create_valid_state();
    
    // Add 101 past DH keys
    for _ in 0..101 {
        state.ratchet.past_dh_recv_publics.push([0; 32]);
    }
    
    let bytes = state.serialize();
    let res = SessionState::deserialize(&bytes);
    assert!(res.is_err(), "Should reject states with > 100 past DH publics");
}
