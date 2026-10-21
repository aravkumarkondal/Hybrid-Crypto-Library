use hybrid_crypto::x25519::{x25519, x25519_base};
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};

// 1. X25519 Invalid Curve / Small Subgroup Attack Simulation
#[test]
fn test_x25519_small_subgroup_attack() {
    let alice_private = [42u8; 32];
    
    // An attacker sends a point of low order (e.g., all zeros) to see if the implementation fails to clear it.
    let malicious_public_key = [0u8; 32];
    
    let shared_secret = hybrid_crypto::x25519::x25519(&alice_private, &malicious_public_key);
    assert!(shared_secret.is_err(), "Shared secret MUST be rejected (InvalidKey) for small subgroup attack point");
}

// 2. AES-GCM Malleability & Forgery Simulation
#[test]
fn test_aes_gcm_ciphertext_malleability() {
    let key = [0x55u8; 32]; // AES-256
    let nonce = [0x11u8; 12];
    let plaintext = b"Top secret bank transfer: $100";
    let aad = b"headers";
    
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes256_gcm_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext);
    
    // Attacker intercepts the ciphertext and flips a bit in the amount
    // Let's modify the last byte (changing the amount)
    let last_idx = ciphertext.len() - 1;
    ciphertext[last_idx] ^= 0x01; 
    
    // Decrypting the modified ciphertext MUST fail authentication
    let mut decrypted_pt = vec![0u8; ciphertext.len()];
    let result = aes256_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag, &mut decrypted_pt);
    assert!(result.is_err(), "AES-GCM MUST reject malleable/forged ciphertext");
}

#[test]
fn test_aes_gcm_nonce_reuse_catastrophe() {
    let key = [0x77u8; 32];
    let nonce = [0x22u8; 12];
    let pt1 = b"Hello Alice, this is Bob.";
    let pt2 = b"Hello Eve,   this is Bob.";
    
    let mut ct1 = vec![0u8; pt1.len()];
    aes256_gcm_encrypt(&key, &nonce, &[], pt1, &mut ct1);
    let mut ct2 = vec![0u8; pt2.len()];
    aes256_gcm_encrypt(&key, &nonce, &[], pt2, &mut ct2);
    
    // The attacker XORs the two ciphertexts together, which cancels the keystream.
    // The result should exactly equal the XOR of the two plaintexts!
    let mut xor_ct = vec![0u8; ct1.len()];
    for i in 0..ct1.len() {
        xor_ct[i] = ct1[i] ^ ct2[i];
    }
    
    let mut xor_pt = vec![0u8; pt1.len()];
    for i in 0..pt1.len() {
        xor_pt[i] = pt1[i] ^ pt2[i];
    }
    
    assert_eq!(xor_ct, xor_pt, "Demonstration of catastrophic nonce reuse failure in CTR mode");
}

#[test]
fn test_aes_gcm_tag_truncation_attack() {
    let key = [0x88u8; 32];
    let nonce = [0x33u8; 12];
    let plaintext = b"Authentic message";
    let mut ciphertext = vec![0u8; plaintext.len()];
    let tag = aes256_gcm_encrypt(&key, &nonce, &[], plaintext, &mut ciphertext);
    
    // Attacker truncates the tag to 8 bytes instead of 16 bytes.
    let truncated_tag: [u8; 16] = {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&tag[..8]);
        t
    };
    
    let mut decrypted_pt = vec![0u8; ciphertext.len()];
    let result = aes256_gcm_decrypt(&key, &nonce, &[], &ciphertext, &truncated_tag, &mut decrypted_pt);
    assert!(result.is_err(), "Tag truncation MUST be rejected");
}

// 3. ML-KEM Chosen Ciphertext Attack (CCA)
#[test]
fn test_ml_kem_cca_implicit_rejection() {
    let entropy = [7u8; 64];
    let m = [3u8; 32];
    
    let (pk, sk) = ml_kem_768_keypair(&entropy);
    let (ct, original_ss) = ml_kem_768_encapsulate(&pk, &m).unwrap();
    
    // Attacker flips a bit in the ciphertext to see if they can learn information
    // about the private key.
    let mut modified_ct = ct;
    modified_ct[50] ^= 0x01;
    
    // Decapsulation MUST return a pseudo-random shared secret instead of failing
    // or returning the original shared secret. This is Implicit Rejection.
    let malicious_ss = ml_kem_768_decapsulate(&sk, &modified_ct);
    
    assert_ne!(malicious_ss, original_ss, "Decapsulated secret MUST differ on modified ciphertext");
    
    // To prove it's pseudorandom, we decapsulate the exact same modified ciphertext again.
    let malicious_ss_2 = ml_kem_768_decapsulate(&sk, &modified_ct);
    assert_eq!(malicious_ss, malicious_ss_2, "Implicit rejection MUST be deterministic based on the ciphertext and private key z-value");
}
