use e2ee::sender_keys::{SenderKeyContext, SenderKeyReceiver};
use e2ee::identity::IdentityKeyPair;
use e2ee::errors::E2EError;

#[test]
fn test_sender_key_identity_spoofing_rejected() {
    let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let mallory_identity = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let group_id = [9; 32];
    let seed = [10; 32];

    let alice_context = SenderKeyContext::new(alice_identity, &group_id, &seed, 1);
    let dist_msg = futures::executor::block_on(alice_context.get_distribution_message());
    let mut bob_receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);

    // Mallory creates a message spoofing Alice's group_id and chain_id
    let mut mallory_context = SenderKeyContext::new(mallory_identity, &group_id, &seed, 1);
    let mallory_msg = futures::executor::block_on(mallory_context.encrypt(b"Malicious injection")).unwrap();

    // Bob must reject Mallory's message because msg.sender_identity does not match the bound identity
    let err = bob_receiver.decrypt(&mallory_msg).unwrap_err();
    assert!(matches!(err, E2EError::InvalidMessageFormat));

    // Mallory attempts to overwrite sender_identity on the message with Alice's identity
    let mut tampered_msg = mallory_msg;
    tampered_msg.sender_identity = dist_msg.sender_identity.clone();

    // Bob must reject because the signature was computed with Mallory's key, not Alice's
    let err2 = bob_receiver.decrypt(&tampered_msg).unwrap_err();
    assert!(matches!(err2, E2EError::InvalidSignature));
}

#[test]
fn test_sender_key_atomic_rollback_on_failed_decryption() {
    let alice_identity = IdentityKeyPair::generate(&[5; 32], &[6; 32]);
    let group_id = [11; 32];
    let seed = [12; 32];

    let mut alice_context = SenderKeyContext::new(alice_identity, &group_id, &seed, 42);
    let dist_msg = futures::executor::block_on(alice_context.get_distribution_message());
    let mut bob_receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);

    let initial_iteration = bob_receiver.chain.iteration;

    // Alice produces a valid message
    let valid_msg = futures::executor::block_on(alice_context.encrypt(b"Legitimate payload")).unwrap();

    // Adversary creates tampered message with corrupted auth tag
    let mut tampered_msg = valid_msg.clone();
    tampered_msg.auth_tag[0] ^= 0x55;
    
    let err = bob_receiver.decrypt(&tampered_msg).unwrap_err();
    assert!(matches!(err, E2EError::InvalidSignature));
    assert_eq!(bob_receiver.chain.iteration, initial_iteration, "Chain iteration must not advance on signature error");

    // Now verify legitimate message decrypts and advances chain exactly once
    let plaintext = bob_receiver.decrypt(&valid_msg).unwrap();
    assert_eq!(plaintext, b"Legitimate payload");
    assert_eq!(bob_receiver.chain.iteration, initial_iteration + 1);

    // Replay attack with the same message must fail with MessageOutOfOrder
    let replay_err = bob_receiver.decrypt(&valid_msg).unwrap_err();
    assert!(matches!(replay_err, E2EError::MessageOutOfOrder));
}
