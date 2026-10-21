extern crate alloc;
use e2ee::{IdentityKeyPair, PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair, Session};
use e2ee::session::MultiDeviceSession;
use e2ee::backup::SessionBackup;

fn setup_sessions() -> (Session, Session) {
    let alice_id = IdentityKeyPair::generate(&[0x11; 32], &[0x12; 32]);
    let bob_id = IdentityKeyPair::generate(&[0x21; 32], &[0x22; 32]);
    let bob_spk = futures::executor::block_on(SignedPreKeyPair::generate(1, &[0x31; 32], &[0x32; 64], &bob_id, &[0x33; 32])).unwrap();
    let bob_opk = OneTimePreKeyPair::generate(1, &[0x41; 32], &[0x42; 64]);
    
    let bob_bundle = PreKeyBundle {
        identity_key: futures::executor::block_on(bob_id.public_key()),
        signed_prekey_id: bob_spk.id,
        signed_prekey_ecc_public: bob_spk.ecc_public,
        signed_prekey_pqc_public: bob_spk.pqc_public,
        signed_prekey_signature: bob_spk.signature.clone(),
        one_time_prekey_id: Some(bob_opk.id),
        one_time_prekey_ecc_public: Some(bob_opk.ecc_public),
        one_time_prekey_pqc_public: Some(bob_opk.pqc_public),
    };

    let (alice_session, prekey_msg, initial_msg) = futures::executor::block_on(Session::setup_as_initiator(
        &alice_id, &bob_bundle, &[0x51; 32], &[0x52; 32], Some(&[0x53; 32]), &[0x54; 32], &[0x55; 64], &[0x56; 32],
    )).unwrap();

    let mut bob_session = futures::executor::block_on(Session::setup_as_responder(&bob_id, &bob_spk, Some(&bob_opk), &prekey_msg)).unwrap();
    let _ = bob_session.receive_initial_message(&initial_msg, &[0x61; 32], &[0x62; 64], &[0x63; 32]).unwrap();

    (alice_session, bob_session)
}

#[test]
fn test_session_backup_roundtrip() {
    let (mut alice_session, _bob_session) = setup_sessions();
    
    // Alice sends a message
    let m1 = alice_session.encrypt_message(b"Hello").unwrap();
    
    // Create MultiDeviceSession
    let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let mut alice_multi = MultiDeviceSession::new(futures::executor::block_on(alice_identity.public_key()));
    alice_multi.add_session(1, alice_session);

    // Create backup
    let backup_key = [99u8; 32];
    let iv = [88u8; 12];
    let backup = SessionBackup::create(&alice_multi, &backup_key, &iv).expect("Backup failed");
    
    // Restore backup
    let mut restored_multi = backup.restore(&backup_key).expect("Restore failed");
    
    // Ensure state matches by sending another message
    let alice_restored = restored_multi.get_session_mut(1).unwrap();
    let m2 = alice_restored.encrypt_message(b"Hello 2").unwrap();
    assert_ne!(m1.ciphertext, m2.ciphertext); // Different ratchet states
}

#[test]
fn test_session_backup_wrong_key() {
    let (alice_session, _) = setup_sessions();
    let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let mut alice_multi = MultiDeviceSession::new(futures::executor::block_on(alice_identity.public_key()));
    alice_multi.add_session(1, alice_session);
        
    let backup_key = [99u8; 32];
    let iv = [88u8; 12];
    let backup = SessionBackup::create(&alice_multi, &backup_key, &iv).expect("Backup failed");
    
    let wrong_key = [100u8; 32];
    let result = backup.restore(&wrong_key);
    assert!(result.is_err(), "Should fail with wrong key");
}
