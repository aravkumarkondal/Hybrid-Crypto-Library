extern crate alloc;
use e2ee::verification_visual::HybridFingerprint;
use e2ee::identity::IdentityKeyPair;
use alloc::vec::Vec;

#[test]
fn test_verification_visual_formats() {
    let alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let device = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    
    let fingerprint = HybridFingerprint::generate(
        &futures::executor::block_on(alice.public_key()),
        &futures::executor::block_on(device.public_key()),
        &[5; 32],
        &[6; 32],
    );

    let numeric_sas = fingerprint.numeric_sas();
    // 32 bytes -> 8 chunks of 4 bytes -> 8 blocks of 5 digits
    let blocks: Vec<&str> = numeric_sas.split(' ').collect();
    assert_eq!(blocks.len(), 8);
    for block in blocks {
        assert_eq!(block.len(), 5);
        assert!(block.chars().all(|c| c.is_digit(10)));
    }

    let pgp_sas = fingerprint.pgp_word_list();
    // 32 bytes -> 32 words separated by hyphens
    let words: Vec<&str> = pgp_sas.split('-').collect();
    assert_eq!(words.len(), 32);
    for word in words {
        assert!(!word.is_empty());
    }
}

#[test]
fn test_verification_visual_collisions() {
    let alice1 = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let device1 = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let fp1 = HybridFingerprint::generate(&futures::executor::block_on(alice1.public_key()), &futures::executor::block_on(device1.public_key()), &[5; 32], &[6; 32]);

    let alice2 = IdentityKeyPair::generate(&[1; 32], &[2; 32]); // same keys
    let device2 = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let fp2 = HybridFingerprint::generate(&futures::executor::block_on(alice2.public_key()), &futures::executor::block_on(device2.public_key()), &[5; 32], &[6; 32]);
    
    // Identical inputs must yield identical fingerprints
    assert_eq!(fp1.as_bytes(), fp2.as_bytes());
    assert_eq!(fp1.numeric_sas(), fp2.numeric_sas());
    assert_eq!(fp1.pgp_word_list(), fp2.pgp_word_list());

    // Single bit change in ephemeral key MUST change fingerprint
    let mut different_ephemeral = [5; 32];
    different_ephemeral[0] ^= 1;
    let fp3 = HybridFingerprint::generate(&futures::executor::block_on(alice1.public_key()), &futures::executor::block_on(device1.public_key()), &different_ephemeral, &[6; 32]);
    
    assert_ne!(fp1.as_bytes(), fp3.as_bytes());
    assert_ne!(fp1.numeric_sas(), fp3.numeric_sas());
    assert_ne!(fp1.pgp_word_list(), fp3.pgp_word_list());
}
