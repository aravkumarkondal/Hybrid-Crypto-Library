#![no_main]
use libfuzzer_sys::fuzz_target;
use hybrid_crypto::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&data[0..64]);
    
    let mut enc_seed = [0u8; 32];
    enc_seed.copy_from_slice(&data[64..96]);

    let (pk, sk) = ml_kem_768_keypair(&seed);
    
    // Encapsulate should not panic
    if let Ok((ct, ss_enc)) = ml_kem_768_encapsulate(&pk, &enc_seed) {
        // Decapsulate should match
        let ss_dec = ml_kem_768_decapsulate(&sk, &ct);
        assert_eq!(ss_enc, ss_dec);
    }
    
    // Fuzz decapsulate directly with random ciphertext bytes
    if data.len() >= 96 + 1088 {
        let mut ct_rand = [0u8; 1088];
        ct_rand.copy_from_slice(&data[96..1184]);
        
        // This should not panic (implicit rejection)
        let _ss_rand = ml_kem_768_decapsulate(&sk, &ct_rand);
    }
});
