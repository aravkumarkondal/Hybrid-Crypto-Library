extern crate alloc;
use e2ee::secret_sharing::ShamirSecretSharing;

#[test]
fn test_gf256_sss_basic() {
    let secret = b"my_super_secret_seed_for_keys123"; // 32 bytes
    let n = 5;
    let m = 3;
    
    // For a 32-byte secret and m=3, we need 32 * (3-1) = 64 bytes of random coefficients
    let mut random_coefficients = alloc::vec![0u8; 64];
    for (i, b) in random_coefficients.iter_mut().enumerate() {
        *b = (i % 255 + 1) as u8; // Dummy entropy for test
    }
    
    // Split
    let shares = ShamirSecretSharing::split_secret(secret, n, m, &random_coefficients)
        .expect("Failed to split secret");
        
    assert_eq!(shares.len(), 5);
    
    // Recover with EXACTLY m shares (e.g., shares 0, 1, 4)
    let subset = alloc::vec![
        shares[0].clone(),
        shares[1].clone(),
        shares[4].clone(),
    ];
    
    let recovered = ShamirSecretSharing::reconstruct_secret(&subset, m)
        .expect("Failed to reconstruct");
        
    assert_eq!(recovered, secret);
    
    // Recover with DIFFERENT m shares (e.g., shares 2, 3, 4)
    let subset2 = alloc::vec![
        shares[2].clone(),
        shares[3].clone(),
        shares[4].clone(),
    ];
    
    let recovered2 = ShamirSecretSharing::reconstruct_secret(&subset2, m)
        .expect("Failed to reconstruct");
        
    assert_eq!(recovered2, secret);
}

#[test]
fn test_gf256_sss_failure_with_m_minus_1() {
    let secret = b"another_secret_seed_for_keys4567"; // 32 bytes
    let n = 5;
    let m = 4;
    
    // For a 32-byte secret and m=4, we need 32 * 3 = 96 bytes
    let mut random_coefficients = alloc::vec![0u8; 96];
    for (i, b) in random_coefficients.iter_mut().enumerate() {
        *b = (i % 255 + 1) as u8;
    }
    
    let shares = ShamirSecretSharing::split_secret(secret, n, m, &random_coefficients)
        .expect("Failed to split secret");
        
    // Try to recover with m - 1 shares (3 shares)
    let subset = alloc::vec![
        shares[0].clone(),
        shares[2].clone(),
        shares[4].clone(),
    ];
    
    // It should either return an error due to insufficient shares (we coded it this way)
    // or if we forced it by passing m=3 to the reconstruct function, it should produce garbage
    
    let err = ShamirSecretSharing::reconstruct_secret(&subset, m);
    assert!(err.is_err());
    
    // What if we try to trick the reconstruct function into thinking m=3?
    let forced_recovered = ShamirSecretSharing::reconstruct_secret(&subset, 3)
        .expect("Failed to reconstruct with forced m");
        
    // The recovered secret should NOT match the original secret
    assert_ne!(forced_recovered, secret);
}
