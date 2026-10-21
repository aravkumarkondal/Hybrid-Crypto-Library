extern crate alloc;

use e2ee::secret_sharing::{ShamirSecretSharing, SecretShare};
use e2ee::errors::E2EError;

#[test]
fn test_secret_sharing_invalid_parameters() {
    let secret = b"super secret message";
    let rand = alloc::vec![0u8; secret.len() * 5];
    
    // m == 0
    let res = ShamirSecretSharing::split_secret(secret, 5, 0, &rand);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // n == 0
    let res = ShamirSecretSharing::split_secret(secret, 0, 3, &rand);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // m > n
    let res = ShamirSecretSharing::split_secret(secret, 3, 5, &rand);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // Invalid random coefficients length
    let bad_rand = alloc::vec![0u8; secret.len() * 2];
    let res = ShamirSecretSharing::split_secret(secret, 5, 4, &bad_rand);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
}

#[test]
fn test_secret_sharing_reconstruct_invalid() {
    let shares = alloc::vec![
        SecretShare { x: 1, y: alloc::vec![1, 2, 3] },
        SecretShare { x: 2, y: alloc::vec![4, 5, 6] },
    ];
    
    // Not enough shares
    let res = ShamirSecretSharing::reconstruct_secret(&shares, 3);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // Mismatched lengths
    let bad_shares = alloc::vec![
        SecretShare { x: 1, y: alloc::vec![1, 2, 3] },
        SecretShare { x: 2, y: alloc::vec![4, 5] },
        SecretShare { x: 3, y: alloc::vec![7, 8, 9] },
    ];
    let res = ShamirSecretSharing::reconstruct_secret(&bad_shares, 3);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
    
    // Duplicate x values (divide by zero protection)
    let dup_shares = alloc::vec![
        SecretShare { x: 1, y: alloc::vec![1, 2, 3] },
        SecretShare { x: 1, y: alloc::vec![4, 5, 6] }, // Duplicate!
        SecretShare { x: 3, y: alloc::vec![7, 8, 9] },
    ];
    let res = ShamirSecretSharing::reconstruct_secret(&dup_shares, 3);
    assert!(matches!(res, Err(E2EError::InvalidMessageFormat)));
}

#[test]
fn test_secret_sharing_gf_math() {
    // We already have a round trip test in the main module,
    // but we can ensure that 0 secret byte works.
    let secret = alloc::vec![0u8; 10];
    let rand = alloc::vec![42u8; 10 * 2]; // m=3, so 2 coefficients per byte
    
    let shares = ShamirSecretSharing::split_secret(&secret, 5, 3, &rand).unwrap();
    let reconstructed = ShamirSecretSharing::reconstruct_secret(&shares, 3).unwrap();
    assert_eq!(secret, reconstructed);
}
