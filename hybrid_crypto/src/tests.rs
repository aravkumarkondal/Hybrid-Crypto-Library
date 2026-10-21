#[cfg(test)]
mod kat_tests {
    use crate::*;

    // =========================================
    // SHA-256 Known Answer Tests (FIPS 180-4)
    // =========================================

    #[test]
    #[cfg(feature = "sha3")]
    fn test_sha256_kat_empty() {
        let hash = sha2::Sha256::new();
        let result = hash.finalize();
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected, "SHA-256 empty string KAT failed");
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_sha256_kat_abc() {
        let mut hash = sha2::Sha256::new();
        hash.update(b"abc");
        let result = hash.finalize();
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(result, expected, "SHA-256 'abc' KAT failed");
    }

    // =========================================
    // SHA3-256 Known Answer Tests (FIPS 202)
    // =========================================

    #[test]
    #[cfg(feature = "sha3")]
    fn test_sha3_256_kat_abc() {
        let result = keccak::sha3_256(b"abc");
        let expected: [u8; 32] = [
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        ];
        assert_eq!(result, expected, "SHA3-256 'abc' KAT failed");
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_sha3_512_kat_empty() {
        let result = keccak::sha3_512(b"");
        let expected: [u8; 64] = [
            0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
            0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
            0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
            0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
        ];
        assert_eq!(result, expected, "SHA3-512 empty KAT failed");
    }

    // =========================================
    // SHAKE128 / SHAKE256 Known Answer Tests
    // =========================================

    #[test]
    #[cfg(feature = "sha3")]
    fn test_shake128_kat_empty() {
        let mut out = [0u8; 32];
        keccak::shake128(b"", &mut out);
        let expected: [u8; 32] = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
            0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
        ];
        assert_eq!(out, expected, "SHAKE128 empty KAT failed");
    }

    #[test]
    #[cfg(feature = "sha3")]
    fn test_shake256_kat_empty() {
        let mut out = [0u8; 32];
        keccak::shake256(b"", &mut out);
        let expected: [u8; 32] = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
            0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(out, expected, "SHAKE256 empty KAT failed");
    }

    // =========================================
    // HMAC-SHA256 Known Answer Tests (RFC 4231)
    // =========================================

    #[test]
    #[cfg(feature = "hkdf")]
    fn test_hmac_sha256_rfc4231_tc2() {
        // Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = hkdf::hmac_sha256(key, data);
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(result, expected, "HMAC-SHA256 RFC4231 TC2 failed");
    }

    // =========================================
    // HKDF Known Answer Tests (RFC 5869)
    // =========================================

    #[test]
    #[cfg(feature = "hkdf")]
    fn test_hkdf_rfc5869_tc1() {
        let ikm: [u8; 22] = [0x0b; 22];
        let salt: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk = hkdf::hkdf_extract(&salt, &ikm);
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
            0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk, "HKDF-Extract RFC5869 TC1 failed");

        let mut okm = [0u8; 42];
        hkdf::hkdf_expand(&prk, &info, &mut okm);
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
            0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
            0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected_okm, "HKDF-Expand RFC5869 TC1 failed");
    }

    // =========================================
    // X25519 Known Answer Tests (RFC 7748)
    // =========================================

    #[test]
    #[cfg(feature = "x25519")]
    fn test_x25519_rfc7748_section5_2() {
        // RFC 7748 Section 5.2 — first test vector
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
            0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_coord: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
            0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
        ];
        let result = x25519::x25519(&scalar, &u_coord).unwrap();
        assert_eq!(result, expected, "X25519 RFC7748 Section 5.2 test vector 1 failed");
    }

    #[test]
    #[cfg(feature = "x25519")]
    fn test_x25519_dh_symmetry() {
        // Verify that A*B_pub == B*A_pub (DH symmetry)
        let alice_priv = [7u8; 32];
        let bob_priv = [11u8; 32];

        let alice_pub = x25519::x25519_base(&alice_priv);
        let bob_pub = x25519::x25519_base(&bob_priv);

        let shared_ab = x25519::x25519(&alice_priv, &bob_pub).unwrap();
        let shared_ba = x25519::x25519(&bob_priv, &alice_pub).unwrap();
        assert_eq!(shared_ab, shared_ba, "X25519 DH symmetry failed");
        // Shared secret should not be all zeros (degenerate case)
        assert_ne!(shared_ab, [0u8; 32], "X25519 shared secret is all zeros");
    }

    // =========================================
    // AES-256-GCM Tests
    // =========================================

    #[test]
    #[cfg(feature = "aes-gcm")]
    fn test_aes_gcm_standalone() {
        let key = [1u8; 32];
        let iv = [2u8; 12];
        let plaintext = b"Highly confidential post-quantum secret message";
        let mut ciphertext = alloc::vec![0u8; plaintext.len()];
        let tag1 = crate::aes_gcm::aes256_gcm_encrypt(&key, &iv, &[], plaintext, &mut ciphertext);
        
        let mut decrypted = alloc::vec![0u8; plaintext.len()];
        crate::aes_gcm::aes256_gcm_decrypt(&key, &iv, &[], &ciphertext, &tag1, &mut decrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    #[cfg(feature = "aes-gcm")]
    fn test_nist_gcm() {
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = [0u8; 0];
        let mut ct = alloc::vec![0u8; pt.len()];
        let tag = crate::aes_gcm::aes256_gcm_encrypt(&key, &iv, &aad, &pt, &mut ct);
        
        let expected_tag = [
            0xeb, 0x9f, 0x79, 0x6c, 0x8d, 0x35, 0x6f, 0xc3, 0x1a, 0x84, 0x33, 0x88, 0x4b, 0x69, 0x6f, 0x4f
        ];
        assert_eq!(tag, expected_tag, "AES-256-GCM NIST tag mismatch");

        // Verify decrypt works with correct tag
        let mut dec = alloc::vec![0u8; pt.len()];
        crate::aes_gcm::aes256_gcm_decrypt(&key, &iv, &aad, &ct, &tag, &mut dec).unwrap();
        assert_eq!(dec.as_slice(), &pt, "AES-256-GCM NIST decrypt mismatch");
    }

    #[test]
    #[cfg(feature = "aes-gcm")]
    fn test_gcm_tag_rejection() {
        // Verify that a corrupted tag is rejected
        let key = [1u8; 32];
        let iv = [2u8; 12];
        let plaintext = b"secret data";
        let mut ciphertext = alloc::vec![0u8; plaintext.len()];
        let tag = crate::aes_gcm::aes256_gcm_encrypt(&key, &iv, &[], plaintext, &mut ciphertext);
        
        // Corrupt one byte of the tag
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xFF;
        
        let mut decrypted = alloc::vec![0u8; plaintext.len()];
        let result = crate::aes_gcm::aes256_gcm_decrypt(&key, &iv, &[], &ciphertext, &bad_tag, &mut decrypted);
        assert!(result.is_err(), "GCM must reject corrupted tag");
    }

    #[test]
    #[cfg(feature = "aes-gcm")]
    fn test_gcm_empty_plaintext() {
        // GCM with empty plaintext should produce a valid tag (auth-only mode)
        let key = [0xAAu8; 32];
        let iv = [0xBBu8; 12];
        let plaintext = b"";
        let mut ciphertext = alloc::vec![0u8; 0];
        let tag = crate::aes_gcm::aes256_gcm_encrypt(&key, &iv, &[], plaintext, &mut ciphertext);
        
        // Decrypt should succeed with correct tag
        let mut decrypted = alloc::vec![0u8; 0];
        crate::aes_gcm::aes256_gcm_decrypt(&key, &iv, &[], &ciphertext, &tag, &mut decrypted).unwrap();
    }

    // =========================================
    // Hybrid Encryption Full Cycle
    // =========================================

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_hybrid_encryption_cycle() {
        let entropy_ecc = [1u8; 32];
        let entropy_pqc = [2u8; 64];

        let receiver_keypair = HybridKeyPair::generate(&entropy_ecc, &entropy_pqc);

        let payload = b"Hello, post-quantum world!";
        let entropy_ecc_ephem = [3u8; 32];
        let entropy_pqc_encaps = [4u8; 32];
        let iv = [0u8; 12];

        let package = hybrid_encrypt_payload(
            payload,
            &receiver_keypair.ecc_public,
            &receiver_keypair.pqc_public,
            &entropy_ecc_ephem,
            &entropy_pqc_encaps,
            &iv,
        ).unwrap();

        assert_eq!(package.ciphertext.len(), payload.len());

        let decrypted = hybrid_decrypt_payload(
            &package.ciphertext,
            &package.iv,
            &package.tag,
            &package.ecc_ephemeral_pub,
            &package.pqc_ciphertext,
            &receiver_keypair.ecc_private,
            &receiver_keypair.pqc_private,
        ).expect("Decryption failed");

        assert_eq!(decrypted.as_slice(), payload);
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_hybrid_encryption_large_payload() {
        let entropy_ecc = [10u8; 32];
        let entropy_pqc = [20u8; 64];
        let receiver_keypair = HybridKeyPair::generate(&entropy_ecc, &entropy_pqc);

        // Test with a payload larger than one AES block (16 bytes)
        let payload = [0x42u8; 1024]; // 1KB payload
        let entropy_ecc_ephem = [30u8; 32];
        let entropy_pqc_encaps = [40u8; 32];
        let iv = [0x55u8; 12];

        let package = hybrid_encrypt_payload(
            &payload,
            &receiver_keypair.ecc_public,
            &receiver_keypair.pqc_public,
            &entropy_ecc_ephem,
            &entropy_pqc_encaps,
            &iv,
        ).unwrap();

        let decrypted = hybrid_decrypt_payload(
            &package.ciphertext,
            &package.iv,
            &package.tag,
            &package.ecc_ephemeral_pub,
            &package.pqc_ciphertext,
            &receiver_keypair.ecc_private,
            &receiver_keypair.pqc_private,
        ).expect("Large payload decryption failed");

        assert_eq!(decrypted.as_slice(), &payload[..]);
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn test_hybrid_wrong_key_rejection() {
        let entropy_ecc = [1u8; 32];
        let entropy_pqc = [2u8; 64];
        let receiver_keypair = HybridKeyPair::generate(&entropy_ecc, &entropy_pqc);

        let payload = b"This is a secret";
        let entropy_ecc_ephem = [3u8; 32];
        let entropy_pqc_encaps = [4u8; 32];
        let iv = [5u8; 12];

        let package = hybrid_encrypt_payload(
            payload,
            &receiver_keypair.ecc_public,
            &receiver_keypair.pqc_public,
            &entropy_ecc_ephem,
            &entropy_pqc_encaps,
            &iv,
        ).unwrap();

        // Try decrypting with wrong private key
        let wrong_ecc = [99u8; 32];
        let result = hybrid_decrypt_payload(
            &package.ciphertext,
            &package.iv,
            &package.tag,
            &package.ecc_ephemeral_pub,
            &package.pqc_ciphertext,
            &wrong_ecc,
            &receiver_keypair.pqc_private,
        );
        assert!(result.is_err(), "Decryption with wrong ECC key must fail");
    }

    // =========================================
    // Constant-time utilities
    // =========================================

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2];

        assert!(utils::constant_time_eq(&a, &b));
        assert!(!utils::constant_time_eq(&a, &c));
        assert!(!utils::constant_time_eq(&a, &d));
    }

    #[test]
    fn test_cswap_swap() {
        let mut a = [1u64, 2, 3, 4];
        let mut b = [5u64, 6, 7, 8];
        utils::cswap(1, &mut a, &mut b);
        assert_eq!(a, [5, 6, 7, 8]);
        assert_eq!(b, [1, 2, 3, 4]);
    }

    #[test]
    fn test_cswap_no_swap() {
        let mut a = [1u64, 2, 3, 4];
        let mut b = [5u64, 6, 7, 8];
        utils::cswap(0, &mut a, &mut b);
        assert_eq!(a, [1, 2, 3, 4]);
        assert_eq!(b, [5, 6, 7, 8]);
    }

    #[test]
    fn test_zeroize() {
        let mut data = [0xFFu8; 64];
        utils::zeroize(&mut data);
        assert_eq!(data, [0u8; 64]);
    }

    #[test]
    #[cfg(feature = "ml-kem")]
    fn test_ml_kem_invalid_public_key() {
        let entropy_ecc = [1u8; 32];
        let entropy_pqc = [2u8; 64];
        let mut receiver_keypair = HybridKeyPair::generate(&entropy_ecc, &entropy_pqc);

        // Inject an invalid coefficient (3329) into the first polynomial of the public key.
        // 3329 = 0x0D01
        // b[0] = 0x01, b[1] (lower 4 bits) = 0x0D
        receiver_keypair.pqc_public[0] = 0x01;
        receiver_keypair.pqc_public[1] = (receiver_keypair.pqc_public[1] & 0xF0) | 0x0D;

        let payload = b"Hello";
        let entropy_ecc_ephem = [3u8; 32];
        let entropy_pqc_encaps = [4u8; 32];
        let iv = [0u8; 12];

        let package = hybrid_encrypt_payload(
            payload,
            &receiver_keypair.ecc_public,
            &receiver_keypair.pqc_public,
            &entropy_ecc_ephem,
            &entropy_pqc_encaps,
            &iv,
        );

        assert!(package.is_err(), "Encapsulation MUST fail if public key coefficients >= 3329");
        assert_eq!(package.err().unwrap(), CryptoError::InvalidKey);
    }

    #[test]
    #[cfg(feature = "x25519")]
    fn test_x25519_msb_masking() {
        // RFC 7748 requires implementations to mask the most significant bit of the final byte.
        let scalar = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
            0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xd6,
            0x2e, 0xd5, 0x1b, 0x6a, 0x15, 0x53, 0x44, 0x51,
            0x7c, 0xe5, 0xc2, 0x01, 0x3d, 0x98, 0x47, 0x41
        ];
        
        let point_normal = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
            0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
            0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
            0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
        ];

        let mut point_msb_set = point_normal;
        point_msb_set[31] |= 0x80; // Set MSB

        let res_normal = crate::x25519::x25519(&scalar, &point_normal).unwrap();
        let res_msb_set = crate::x25519::x25519(&scalar, &point_msb_set).unwrap();

        assert_eq!(res_normal, res_msb_set, "Points with MSB set must yield identical shared secrets");
    }
}
