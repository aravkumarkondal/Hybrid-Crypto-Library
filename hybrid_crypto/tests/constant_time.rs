use std::hint::black_box;
use std::time::Instant;
use hybrid_crypto::ml_kem::*;
use hybrid_crypto::ml_dsa::*;

const ITERATIONS: usize = 10000;

#[test]
fn test_ml_kem_768_constant_time() {
    let entropy_kp = [1u8; 64];
    let (pk, sk) = ml_kem_768_keypair(&entropy_kp);
    
    let entropy_enc = [2u8; 32];
    let (ct, _) = ml_kem_768_encapsulate(&pk, &entropy_enc).unwrap();
    
    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 1;
    bad_ct[10] ^= 0xFF;
    
    // Warmup
    for _ in 0..100 {
        black_box(ml_kem_768_decapsulate(&sk, &ct));
        black_box(ml_kem_768_decapsulate(&sk, &bad_ct));
    }
    
    let mut valid_ns = 0;
    let mut invalid_ns = 0;
    
    for _ in 0..ITERATIONS {
        let t1 = Instant::now();
        black_box(ml_kem_768_decapsulate(&sk, &ct));
        valid_ns += t1.elapsed().as_nanos();
        
        let t2 = Instant::now();
        black_box(ml_kem_768_decapsulate(&sk, &bad_ct));
        invalid_ns += t2.elapsed().as_nanos();
    }
    
    let valid_ns = valid_ns as f64;
    let invalid_ns = invalid_ns as f64;
    
    let diff = (valid_ns - invalid_ns).abs();
    let max = valid_ns.max(invalid_ns);
    let delta = diff / max;
    
    println!("ML-KEM-768 Decapsulate Valid: {} ns/iter", valid_ns / ITERATIONS as f64);
    println!("ML-KEM-768 Decapsulate Invalid: {} ns/iter", invalid_ns / ITERATIONS as f64);
    println!("ML-KEM-768 Decapsulate Delta: {:.2}%", delta * 100.0);
    
    assert!(delta < 0.05, "ML-KEM-768 decapsulation is not constant time! Delta: {:.2}%", delta * 100.0);
}

#[test]
fn test_ml_dsa_87_constant_time() {
    let entropy = [3u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&entropy);
    
    let message = b"constant time test message for dsa 87";
    let ctx = b"test_ctx";
    let rnd = [4u8; 32];
    let sig = ml_dsa_87_sign(&sk.0, message, ctx, &rnd).unwrap();
    
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 1;
    bad_sig[100] ^= 0xFF;
    
    // Warmup
    for _ in 0..100 {
        black_box(ml_dsa_87_verify(&pk, message, ctx, &sig));
        black_box(ml_dsa_87_verify(&pk, message, ctx, &bad_sig));
    }
    
    let mut valid_ns = 0;
    let mut invalid_ns = 0;
    
    for _ in 0..ITERATIONS {
        let t1 = Instant::now();
        black_box(ml_dsa_87_verify(&pk, message, ctx, &sig));
        valid_ns += t1.elapsed().as_nanos();
        
        let t2 = Instant::now();
        black_box(ml_dsa_87_verify(&pk, message, ctx, &bad_sig));
        invalid_ns += t2.elapsed().as_nanos();
    }
    
    let valid_ns = valid_ns as f64;
    let invalid_ns = invalid_ns as f64;
    
    let diff = (valid_ns - invalid_ns).abs();
    let max = valid_ns.max(invalid_ns);
    let delta = diff / max;
    
    println!("ML-DSA-87 Verify Valid: {} ns/iter", valid_ns / ITERATIONS as f64);
    println!("ML-DSA-87 Verify Invalid: {} ns/iter", invalid_ns / ITERATIONS as f64);
    println!("ML-DSA-87 Verify Delta: {:.2}%", delta * 100.0);
    
    assert!(delta < 0.05, "ML-DSA-87 verification is not constant time! Delta: {:.2}%", delta * 100.0);
}
