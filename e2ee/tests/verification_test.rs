extern crate alloc;
use e2ee::{IdentityKeyPair, Fingerprint};
use alloc::vec::Vec;

#[test]
fn test_fingerprint_generation_and_formatting() {
    let account = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let device1 = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    let device2 = IdentityKeyPair::generate(&[5; 32], &[6; 32]);

    // Test determinism and order independence
    let fp1 = Fingerprint::compute(&account.public_key(), &[device1.public_key(), device2.public_key()]);
    let fp2 = Fingerprint::compute(&account.public_key(), &[device2.public_key(), device1.public_key()]);
    
    assert_eq!(fp1.hash, fp2.hash, "Fingerprint must be independent of device order.");

    // Test formatting
    let display_string = fp1.to_display_string();
    
    // Format should be 12 blocks of 5 digits separated by space
    let blocks: Vec<&str> = display_string.split(' ').collect();
    assert_eq!(blocks.len(), 12, "Must contain exactly 12 blocks");
    
    for block in blocks {
        assert_eq!(block.len(), 5, "Each block must be exactly 5 digits long");
        assert!(block.chars().all(|c| c.is_ascii_digit()), "Must be numeric");
    }

    // Test collision resistance (different account/devices produce different fingerprints)
    let account_b = IdentityKeyPair::generate(&[7; 32], &[8; 32]);
    let fp3 = Fingerprint::compute(&account_b.public_key(), &[device1.public_key(), device2.public_key()]);
    assert_ne!(fp1.hash, fp3.hash, "Different accounts must yield different fingerprints");
}
