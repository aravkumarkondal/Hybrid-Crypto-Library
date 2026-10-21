use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};

#[test]
fn test_ml_dsa_dos_vulnerability() {
    let mut rng_state = [0u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&mut rng_state);
    
    let message = b"Hello World";
    let mut rnd = [0u8; 32];
    let mut sig = ml_dsa_87_sign(&sk, message, &[], &mut rnd).unwrap();
    
    // Inject a malicious bound at the end of the signature.
    // The hint string is located at the end of the signature.
    // The signature size is 4627. The hints start at 4627 - (75 + 8) = 4544.
    // The bounds are in the last K bytes (8 bytes) of the hint array.
    // So the bounds are at sig.len() - 8 to sig.len() - 1.
    let sig_len = sig.len();
    for i in 0..8 {
        sig[sig_len - 8 + i] = 255; // Set all bounds to 255 (malicious)
    }

    // This should gracefully return false and NOT panic.
    let valid = ml_dsa_87_verify(&pk, message, &[], &sig);
    assert!(!valid);
}
