#![no_main]
use libfuzzer_sys::fuzz_target;
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[0..32]);
    
    let mut rnd = [0u8; 32];
    rnd.copy_from_slice(&data[32..64]);
    
    let msg = &data[64..];
    
    // Keypair should not panic
    let (pk, sk) = ml_dsa_87_keypair(&seed);
    
    // Sign should not panic
    if let Ok(sig) = ml_dsa_87_sign(&sk, msg, &[], &rnd) {
        // Verify should succeed for correct signature
        let is_valid = ml_dsa_87_verify(&pk, msg, &[], &sig);
        assert!(is_valid);
        
        // Fuzz verify with tampered signature
        if !msg.is_empty() {
            let mut tampered_sig = sig.clone();
            tampered_sig[0] ^= 1;
            let _ = ml_dsa_87_verify(&pk, msg, &[], &tampered_sig);
        }
    }
});
