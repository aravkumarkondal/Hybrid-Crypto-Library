use e2ee::{IdentityKeyPair, SenderKeyContext, SenderKeyReceiver};

#[test]
fn test_sender_keys_group_creation_and_distribution() {
    let _alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let group_id = [9; 32];
    let seed = [10; 32];
    
    let mut alice_context = SenderKeyContext::new(IdentityKeyPair::generate(&[1; 32], &[2; 32]), &group_id, &seed, 1);
    let dist_msg = futures::executor::block_on(alice_context.get_distribution_message());
    
    let mut bob_receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);
    let mut charlie_receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);
    
    let pt = b"Group Hello";
    let msg = futures::executor::block_on(alice_context.encrypt(pt)).unwrap();
    
    assert_eq!(bob_receiver.decrypt(&msg).unwrap(), pt);
    assert_eq!(charlie_receiver.decrypt(&msg).unwrap(), pt);
}

#[test]
fn test_sender_keys_rotation_member_removal() {
    let _alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let group_id = [9; 32];
    
    // Initial chain
    let mut alice_ctx = SenderKeyContext::new(IdentityKeyPair::generate(&[1; 32], &[2; 32]), &group_id, &[10; 32], 1);
    let dist_msg1 = futures::executor::block_on(alice_ctx.get_distribution_message());
    let mut bob_recv = SenderKeyReceiver::from_distribution_message(&dist_msg1);
    
    let msg1 = futures::executor::block_on(alice_ctx.encrypt(b"Before removal")).unwrap();
    assert!(bob_recv.decrypt(&msg1).is_ok());

    // Rotate chain (Bob removed)
    let mut alice_ctx_new = SenderKeyContext::new(IdentityKeyPair::generate(&[1; 32], &[2; 32]), &group_id, &[11; 32], 2);
    let dist_msg2 = futures::executor::block_on(alice_ctx_new.get_distribution_message());
    // Bob doesn't get dist_msg2
    
    let msg2 = futures::executor::block_on(alice_ctx_new.encrypt(b"After removal")).unwrap();
    
    // Bob should fail to decrypt msg2 because he doesn't have chain 2
    assert!(bob_recv.decrypt(&msg2).is_err());
    
    // Charlie joins and gets dist_msg2
    let mut charlie_recv = SenderKeyReceiver::from_distribution_message(&dist_msg2);
    assert!(charlie_recv.decrypt(&msg2).is_ok());
}

#[test]
fn test_sender_keys_impersonation_protection() {
    let _alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let eve = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let group_id = [9; 32];
    
    let mut alice_ctx = SenderKeyContext::new(IdentityKeyPair::generate(&[1; 32], &[2; 32]), &group_id, &[10; 32], 1);
    let dist_msg = futures::executor::block_on(alice_ctx.get_distribution_message());
    let mut bob_recv = SenderKeyReceiver::from_distribution_message(&dist_msg);
    
    let mut msg = futures::executor::block_on(alice_ctx.encrypt(b"Legit")).unwrap();
    
    // Eve tries to change the ciphertext but signature validation should fail
    msg.ciphertext[0] ^= 1;
    assert!(bob_recv.decrypt(&msg).is_err());
    
    // Eve tries to sign it with her own key (impersonation)
    // But Bob's receiver expects Alice's signature
    msg.sender_identity = futures::executor::block_on(eve.public_key());
    assert!(bob_recv.decrypt(&msg).is_err());
}
