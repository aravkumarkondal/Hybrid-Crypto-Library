#![cfg(feature = "ml-dsa")]
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};

#[test]
fn test_ml_dsa_87_monte_carlo() {
    let mut seed = [0u8; 32];
    for (i, val) in seed.iter_mut().enumerate() {
        *val = (i * 2) as u8;
    }

    let (pk, sk) = ml_dsa_87_keypair(&seed);
    
    // We run multiple iterations to trigger different rejection sampling paths.
    for i in 0..10 {
        let mut msg = [0u8; 64];
        msg[0] = i as u8;
        
        let mut rnd = [0u8; 32];
        rnd[0] = i as u8;
        
        // This will internally do the FIPS 204 domain separated hash
        // and rejection sampling loops for z and the hint polynomial.
        let sig = ml_dsa_87_sign(&sk, &msg, &[], &rnd).expect("Signing failed");
        
        // Ensure signature size is exact FIPS 204 ML-DSA-87 size (4627 bytes)
        assert_eq!(sig.len(), 4627, "Signature size is not 4627 bytes");
        
        let valid = ml_dsa_87_verify(&pk, &msg, &[], &sig);
        assert!(valid, "ML-DSA-87 Signature verification failed at iteration {}", i);
    }
}

#[test]
fn test_ml_dsa_invalid_signature() {
    let seed = [0u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"test message";
    let rnd = [0u8; 32];
    
    let mut sig = ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap();
    
    // valid sig
    assert!(ml_dsa_87_verify(&pk, msg, &[], &sig), "Valid signature failed verification");
    
    // tampered sig
    sig[0] ^= 1;
    assert!(!ml_dsa_87_verify(&pk, msg, &[], &sig), "Tampered signature bypassed verification");
}

#[test]
fn test_ml_dsa_context() {
    let seed = [0u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"test message";
    let rnd = [0u8; 32];
    
    let valid_ctx = [0u8; 255];
    let sig = ml_dsa_87_sign(&sk, msg, &valid_ctx, &rnd).unwrap();
    assert!(ml_dsa_87_verify(&pk, msg, &valid_ctx, &sig), "Valid context failed verification");
    
    // wrong context
    let wrong_ctx = [1u8; 255];
    assert!(!ml_dsa_87_verify(&pk, msg, &wrong_ctx, &sig), "Wrong context bypassed verification");
    
    // context too long
    let invalid_ctx = [0u8; 256];
    assert!(ml_dsa_87_sign(&sk, msg, &invalid_ctx, &rnd).is_err(), "Context > 255 bytes must be rejected");
}

#[test]
fn test_ml_dsa_modified_message() {
    let seed = [0u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"original message";
    let rnd = [0u8; 32];
    
    let sig = ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap();
    
    let msg_mod = b"original msssage"; // 1 byte different
    assert!(!ml_dsa_87_verify(&pk, msg_mod, &[], &sig), "Modified message bypassed verification");
}

#[test]
fn test_ml_dsa_truncated_signature() {
    let seed = [0u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    let msg = b"test message";
    let rnd = [0u8; 32];
    
    let sig = ml_dsa_87_sign(&sk, msg, &[], &rnd).unwrap();
    
    assert!(!ml_dsa_87_verify(&pk, msg, &[], &sig[..sig.len()-1]), "Truncated signature bypassed verification");
    assert!(!ml_dsa_87_verify(&pk, msg, &[], &sig[..sig.len()/2]), "Half signature bypassed verification");
    assert!(!ml_dsa_87_verify(&pk, msg, &[], &[]), "Empty signature bypassed verification");
}

#[test]
fn test_ml_dsa_forgery_attempts() {
    let seed1 = [1u8; 32];
    let seed2 = [2u8; 32];
    let (pk1, _) = ml_dsa_87_keypair(&seed1);
    let (_, sk2) = ml_dsa_87_keypair(&seed2);
    let msg = b"test message";
    let rnd = [0u8; 32];
    
    let sig2 = ml_dsa_87_sign(&sk2, msg, &[], &rnd).unwrap();
    
    // Key mismatch
    assert!(!ml_dsa_87_verify(&pk1, msg, &[], &sig2), "Signature from different key bypassed verification");
    
    // Completely random signature
    let mut fake_sig = vec![0u8; 4627];
    for (i, v) in fake_sig.iter_mut().enumerate() { *v = (i % 256) as u8; }
    assert!(!ml_dsa_87_verify(&pk1, msg, &[], &fake_sig), "Random signature bypassed verification");
}
