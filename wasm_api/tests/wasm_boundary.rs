#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use wasm_api::{
    WasmIdentityKeyPair, WasmSenderKeyContext, WasmSenderKeyReceiver, WasmSession,
};
use e2ee::state::{DoubleRatchetState, SessionState};
use e2ee::serialization::Serialize;



#[wasm_bindgen_test]
fn test_wasm_boundary() {
    // 1. Generate keys
    let entropy_ecc = [1u8; 32];
    let entropy_pqc = [2u8; 32];
    let key_pair = WasmIdentityKeyPair::new(&entropy_ecc, &entropy_pqc).expect("Failed to generate keys");
    let pub_key = key_pair.public_key();
    let pub_key_bytes = pub_key.serialize();
    assert!(!pub_key_bytes.is_empty(), "Public key serialization failed");

    // 2. Instantiate a SenderKey session to encrypt and decrypt
    let group_id = [3u8; 32];
    let seed = [4u8; 32];
    let mut sender_ctx = WasmSenderKeyContext::new(&entropy_ecc, &entropy_pqc, &group_id, &seed, 1)
        .expect("Failed to create SenderKeyContext");

    let dist_msg = sender_ctx.get_distribution_message();
    let mut receiver_ctx = WasmSenderKeyReceiver::from_distribution_message(&dist_msg)
        .expect("Failed to create SenderKeyReceiver");

    let plaintext = b"Hello WASM boundary!";
    let ciphertext = sender_ctx.encrypt(plaintext).expect("Encryption failed");
    let decrypted = receiver_ctx.decrypt(&ciphertext).expect("Decryption failed");

    assert_eq!(plaintext.as_slice(), decrypted.as_slice(), "Decrypted text does not match");

    // 3. Instantiate a WasmSession object via JS/WASM interop (restore_state)
    let dummy_ratchet = DoubleRatchetState {
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
        skipped_message_keys: vec![],
        past_dh_recv_publics: vec![],
    };
    let session_state = SessionState::new(dummy_ratchet, Some([18; 1088]));
    let session_bytes = session_state.serialize();

    let restored_session = WasmSession::restore_state(&session_bytes).expect("Failed to restore WasmSession");
    let exported_bytes = restored_session.export_state();
    assert!(!exported_bytes.is_empty(), "Exported session state should not be empty");
}
