#![cfg(feature = "ml-kem")]
use hybrid_crypto::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};

#[test]
fn test_ml_kem_768_monte_carlo() {
    let mut seed = [0u8; 64];
    for (i, val) in seed.iter_mut().enumerate() {
        *val = i as u8;
    }

    let (pk, sk) = ml_kem_768_keypair(&seed);

    for i in 0..100 {
        let mut enc_seed = [0u8; 32];
        enc_seed[0] = i as u8;
        
        let (ct, ss_enc) = ml_kem_768_encapsulate(&pk, &enc_seed).unwrap();
        let ss_dec = ml_kem_768_decapsulate(&sk, &ct);
        
        assert_eq!(ss_enc, ss_dec, "ML-KEM-768 Decapsulation failed at iteration {}", i);
    }
}

#[test]
fn test_ml_kem_implicit_rejection() {
    let seed = [0x5A; 64];
    let (pk, sk) = ml_kem_768_keypair(&seed);
    let enc_seed = [0x99; 32];
    let (mut ct, ss_enc) = ml_kem_768_encapsulate(&pk, &enc_seed).unwrap();
    
    // Tamper with the ciphertext
    ct[0] ^= 1;
    
    let ss_dec = ml_kem_768_decapsulate(&sk, &ct);
    
    // Implicit rejection means it MUST NOT panic and MUST return a completely different key
    assert_ne!(ss_enc, ss_dec, "Tampered ciphertext returned original secret (implicit rejection failed)");
    
    // It should be deterministic for the same tampered ciphertext
    let ss_dec2 = ml_kem_768_decapsulate(&sk, &ct);
    assert_eq!(ss_dec, ss_dec2, "Implicit rejection is not deterministic");
}

#[test]
fn test_ml_kem_randomized_inputs() {
    let mut seed = [0u8; 64];
    for i in 0..64 { seed[i] = (i * 7) as u8; }
    let (pk, sk) = ml_kem_768_keypair(&seed);
    
    let mut enc_seed1 = [0u8; 32];
    let mut enc_seed2 = [0u8; 32];
    for i in 0..32 {
        enc_seed1[i] = (i * 3) as u8;
        enc_seed2[i] = (i * 5) as u8;
    }
    
    let (ct1, ss1) = ml_kem_768_encapsulate(&pk, &enc_seed1).unwrap();
    let (ct2, ss2) = ml_kem_768_encapsulate(&pk, &enc_seed2).unwrap();
    
    assert_ne!(ct1, ct2, "Different randomness should produce different ciphertexts");
    assert_ne!(ss1, ss2, "Different randomness should produce different shared secrets");
    
    let dec_ss1 = ml_kem_768_decapsulate(&sk, &ct1);
    let dec_ss2 = ml_kem_768_decapsulate(&sk, &ct2);
    
    assert_eq!(ss1, dec_ss1, "Decapsulation failed for input 1");
    assert_eq!(ss2, dec_ss2, "Decapsulation failed for input 2");
}

#[test]
fn test_ml_kem_boundary_conditions() {
    // All zeros seed
    let seed_zeros = [0u8; 64];
    let (pk_z, sk_z) = ml_kem_768_keypair(&seed_zeros);
    let enc_seed_zeros = [0u8; 32];
    let (ct_z, ss_enc_z) = ml_kem_768_encapsulate(&pk_z, &enc_seed_zeros).unwrap();
    let ss_dec_z = ml_kem_768_decapsulate(&sk_z, &ct_z);
    assert_eq!(ss_enc_z, ss_dec_z, "All zeros boundary condition failed");

    // All ones seed
    let seed_ones = [0xFF; 64];
    let (pk_o, sk_o) = ml_kem_768_keypair(&seed_ones);
    let enc_seed_ones = [0xFF; 32];
    let (ct_o, ss_enc_o) = ml_kem_768_encapsulate(&pk_o, &enc_seed_ones).unwrap();
    let ss_dec_o = ml_kem_768_decapsulate(&sk_o, &ct_o);
    assert_eq!(ss_enc_o, ss_dec_o, "All ones boundary condition failed");
}
