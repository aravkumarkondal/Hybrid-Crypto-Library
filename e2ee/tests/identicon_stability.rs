extern crate alloc;

use e2ee::verification_visual::HybridFingerprint;
use e2ee::identicon::Identicon;
use e2ee::identity::IdentityKeyPair;

#[test]
fn test_identicon_stability_and_symmetry() {
    let alice = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let device = IdentityKeyPair::generate(&[3; 32], &[4; 32]);
    
    let fingerprint1 = HybridFingerprint::generate(
        &futures::executor::block_on(alice.public_key()),
        &futures::executor::block_on(device.public_key()),
        &[5; 32],
        &[6; 32],
    );
    
    let identicon1 = Identicon::generate(&fingerprint1);
    
    assert_eq!(identicon1.grid.len(), 8);
    
    for row in 0..8 {
        assert_eq!(identicon1.grid[row].len(), 8);
        for col in 0..4 {
            // Assert vertical symmetry
            assert_eq!(identicon1.grid[row][col], identicon1.grid[row][7 - col]);
        }
    }
    
    // Test determinism
    let fingerprint2 = HybridFingerprint::generate(
        &futures::executor::block_on(alice.public_key()),
        &futures::executor::block_on(device.public_key()),
        &[5; 32],
        &[6; 32],
    );
    
    let identicon2 = Identicon::generate(&fingerprint2);
    
    for row in 0..8 {
        for col in 0..8 {
            assert_eq!(identicon1.grid[row][col], identicon2.grid[row][col]);
        }
    }

    // Different inputs must produce different identicons (with very high probability).
    // A single bit change in ephemeral keys
    let mut different_ephemeral = [5; 32];
    different_ephemeral[0] ^= 1;
    let fingerprint3 = HybridFingerprint::generate(
        &futures::executor::block_on(alice.public_key()),
        &futures::executor::block_on(device.public_key()),
        &different_ephemeral,
        &[6; 32],
    );
    
    let identicon3 = Identicon::generate(&fingerprint3);
    
    let mut is_different = false;
    for row in 0..8 {
        for col in 0..8 {
            if identicon1.grid[row][col] != identicon3.grid[row][col] {
                is_different = true;
                break;
            }
        }
    }
    assert!(is_different, "Identicons should differ for different inputs");
}
