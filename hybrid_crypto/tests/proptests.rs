use proptest::prelude::*;
use proptest::collection::vec;
use hybrid_crypto::ml_dsa_math::{ntt, intt};
use hybrid_crypto::hkdf::{hkdf_extract, hkdf_expand};
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::ml_kem::ml_kem_768_decapsulate;
use hybrid_crypto::signature::verify;

proptest! {
    // 1. Poly Multiplication (ntt_test module logic): inverse_ntt(ntt(x)) == x
    #[test]
    fn test_ntt_inverse_property(mut poly in proptest::collection::vec(-4000000..4000000i32, 256)) {
        let mut p = [0i32; 256];
        p.copy_from_slice(&poly);
        let original = p;
        
        ntt(&mut p);
        intt(&mut p);
        
        for i in 0..256 {
            let mut val = p[i] % 8380417;
            if val < 0 { val += 8380417; }
            let mut orig = original[i] % 8380417;
            if orig < 0 { orig += 8380417; }
            prop_assert_eq!(val, orig);
        }
    }

    // 2. HKDF edge cases (arbitrary length inputs up to constraints).
    #[test]
    fn test_hkdf_fuzzing(
        salt in vec(any::<u8>(), 0..200),
        ikm in vec(any::<u8>(), 0..200),
        info in vec(any::<u8>(), 0..200),
        out_len in 0..1000usize
    ) {
        let prk = hkdf_extract(&salt, &ikm);
        prop_assert_eq!(prk.len(), 32);
        
        let mut okm = std::vec::Vec::with_capacity(out_len);
        okm.resize(out_len, 0);
        // hkdf_expand could panic if out_len > 255 * 32, but 1000 is fine.
        hkdf_expand(&prk, &info, &mut okm);
        prop_assert_eq!(okm.len(), out_len);
    }

    // 3. AES-GCM (random keys, random nounces, random plaintext).
    #[test]
    fn test_aes_gcm_property(
        key_bytes in any::<[u8; 32]>(),
        iv_bytes in any::<[u8; 12]>(),
        aad in vec(any::<u8>(), 0..100),
        plaintext in vec(any::<u8>(), 0..1000)
    ) {
        let mut ciphertext = std::vec::Vec::with_capacity(plaintext.len());
        ciphertext.resize(plaintext.len(), 0);
        
        let tag = aes256_gcm_encrypt(&key_bytes, &iv_bytes, &aad, &plaintext, &mut ciphertext);
        
        let mut decrypted = std::vec::Vec::with_capacity(ciphertext.len());
        decrypted.resize(ciphertext.len(), 0);
        
        let result = aes256_gcm_decrypt(&key_bytes, &iv_bytes, &aad, &ciphertext, &tag, &mut decrypted);
        prop_assert!(result.is_ok());
        prop_assert_eq!(&plaintext, &decrypted);
        
        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 0x01;
            let mut decrypted2 = std::vec::Vec::with_capacity(ciphertext.len());
            decrypted2.resize(ciphertext.len(), 0);
            let result2 = aes256_gcm_decrypt(&key_bytes, &iv_bytes, &aad, &tampered, &tag, &mut decrypted2);
            prop_assert!(result2.is_err());
        }
        
        // Tamper with tag
        let mut tampered_tag = tag;
        tampered_tag[0] ^= 0x01;
        let mut decrypted3 = std::vec::Vec::with_capacity(ciphertext.len());
        decrypted3.resize(ciphertext.len(), 0);
        let result3 = aes256_gcm_decrypt(&key_bytes, &iv_bytes, &aad, &ciphertext, &tampered_tag, &mut decrypted3);
        prop_assert!(result3.is_err());
    }

    // 4. Random byte fuzzing for ML-KEM Decapsulation
    #[test]
    fn test_ml_kem_decapsulate_fuzzing(
        priv_key in any::<[u8; 2400]>(),
        ciphertext in any::<[u8; 1088]>()
    ) {
        // Just ensuring it does not panic.
        let _ = ml_kem_768_decapsulate(&priv_key, &ciphertext);
    }
    
    // Test encapsulation as well just to be safe with "only return Err"
    #[test]
    fn test_ml_kem_encapsulate_fuzzing(
        pub_key in any::<[u8; 1184]>(),
        entropy in any::<[u8; 32]>()
    ) {
        let _ = hybrid_crypto::ml_kem::ml_kem_768_encapsulate(&pub_key, &entropy);
    }

    // 5. Random byte fuzzing for ML-DSA Verification
    #[test]
    fn test_ml_dsa_verify_fuzzing(
        message in vec(any::<u8>(), 0..200),
        signature in vec(any::<u8>(), 0..5000), // Max valid signature is 4627 bytes, fuzz around there
        public_key in vec(any::<u8>(), 0..2600) // Max valid pubkey is 2592 bytes
    ) {
        let result = verify(&message, &signature, &public_key);
        // It should almost certainly return false for random inputs.
        prop_assert_eq!(result, false);
    }
}
