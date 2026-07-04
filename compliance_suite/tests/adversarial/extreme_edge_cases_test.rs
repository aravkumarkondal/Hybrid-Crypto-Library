use hybrid_crypto::x25519::x25519;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use hybrid_crypto::ml_kem::{ml_kem_768_encapsulate};
use hybrid_crypto::keccak::{shake256, sha3_512};
use hybrid_crypto::CryptoError;

#[test]
fn test_ml_dsa_signature_malleability() {
    let entropy = [42u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&entropy);
    let message = b"Critical instruction: launch missiles";
    let ctx = b"context";
    
    let mut sig = ml_dsa_87_sign(&sk, message, ctx, &[0x99; 32]).unwrap();
    
    // Test base validity
    // Note: ml_dsa_87_verify signature is (pk, msg, ctx, sig)
    let is_valid = ml_dsa_87_verify(&pk, message, ctx, &sig);
    assert!(is_valid);
    
    // Malleability attack: Flip a single bit in the signature hint (e.g., at byte 2000)
    sig[2000] ^= 0x01;
    
    // Verification MUST strictly reject the mutated signature
    let is_valid_now = ml_dsa_87_verify(&pk, message, ctx, &sig);
    assert!(!is_valid_now, "ML-DSA MUST reject mathematically malleable signatures");
}

#[test]
fn test_hash_function_sponge_exhaustion() {
    // Generate a 1 Megabyte payload to completely exhaust the SHAKE/SHA3 internal sponge rate
    let massive_payload = vec![0xABu8; 1_000_000];
    
    // Test SHA3-512 state absorption
    let sha3_out = sha3_512(&massive_payload);
    assert_ne!(sha3_out, [0u8; 64], "SHA3-512 MUST safely absorb massive buffers without panicking or yielding zeros");
    
    // Test SHAKE-256 state absorption and massive squeezing
    let mut massive_out = vec![0u8; 1_000_000];
    shake256(&massive_payload, &mut massive_out);
    
    assert_ne!(massive_out[999_999], 0, "SHAKE-256 MUST safely squeeze massive buffers out of the sponge without panicking");
}

#[test]
fn test_aes_gcm_empty_boundary_conditions() {
    let key = [0x55u8; 32];
    let nonce = [0x11u8; 12];
    
    // 1. Both empty plaintext and empty AAD
    let mut ct1 = vec![0u8; 0];
    let tag1 = aes256_gcm_encrypt(&key, &nonce, &[], &[], &mut ct1);
    
    let mut pt1 = vec![0u8; 0];
    let res1 = aes256_gcm_decrypt(&key, &nonce, &[], &ct1, &tag1, &mut pt1);
    assert!(res1.is_ok(), "AES-GCM MUST support empty plaintexts and AAD");
    
    // 2. Empty plaintext, MASSIVE AAD
    let massive_aad = vec![0xCCu8; 1_000_000];
    let mut ct2 = vec![0u8; 0];
    let tag2 = aes256_gcm_encrypt(&key, &nonce, &massive_aad, &[], &mut ct2);
    
    let mut pt2 = vec![0u8; 0];
    let res2 = aes256_gcm_decrypt(&key, &nonce, &massive_aad, &ct2, &tag2, &mut pt2);
    assert!(res2.is_ok(), "AES-GCM MUST support empty plaintexts with massive AAD");
}

#[test]
fn test_ml_kem_malformed_fuzzing() {
    let pk = [0u8; 1184]; // All zeros public key
    let m = [0u8; 32];
    
    // The ML-KEM spec says if the public key is invalid, it should fail gracefully or implicitly reject.
    // Encapsulation against an all-zero public key will successfully generate a ciphertext (since all polynomials are valid)
    // The key here is that it DOES NOT PANIC when fed completely zeroized or malformed fuzz data!
    let res = ml_kem_768_encapsulate(&pk, &m);
    
    assert!(res.is_ok(), "ML-KEM MUST gracefully process or reject fuzz data without panicking");
}
