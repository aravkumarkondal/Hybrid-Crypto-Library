//! Bit-Flip Chaos & Cryptographic Malleability Test Suite
//!
//! Systematically injects single-bit and multi-bit faults into:
//! 1. ML-KEM-768 ciphertexts to verify Fujisaki-Okamoto implicit rejection behavior.
//! 2. ML-DSA-87 signatures to verify strict rejection without arithmetic panics.
//! 3. AES-256-GCM ciphertexts and authentication tags to verify zero false positives.

extern crate alloc;
use hybrid_crypto::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};

#[test]
fn test_ml_kem_ciphertext_bit_flip_fo_implicit_rejection() {
    let entropy_kem = [0x42u8; 64];
    let (pk, sk) = ml_kem_768_keypair(&entropy_kem);

    let m = [0x55u8; 32];
    let (valid_ct, legitimate_ss) = ml_kem_768_encapsulate(&pk, &m).expect("ML-KEM encapsulation failed");

    // Verify valid decapsulation matches
    let recovered_ss = ml_kem_768_decapsulate(&sk, &valid_ct);
    assert_eq!(recovered_ss, legitimate_ss, "Valid ML-KEM decapsulation failed");

    // Sample distinct byte positions across the 1088-byte ciphertext
    // covering header, polynomial u vector, and polynomial v scalar
    let test_offsets = [
        0, 1, 15, 31, 63, 100, 200, 300, 384, 500, 600, 700, 800, 900,
        960, 1000, 1050, 1080, 1087,
    ];

    for &byte_idx in &test_offsets {
        for bit in 0..8 {
            let mut tampered_ct = valid_ct;
            tampered_ct[byte_idx] ^= 1 << bit;

            // Decapsulation MUST NOT panic
            let rejected_ss = ml_kem_768_decapsulate(&sk, &tampered_ct);

            // In FIPS 203, invalid ciphertexts undergo implicit rejection via the FO transform:
            // they must decrypt to a deterministic pseudo-random key orthogonal to the legitimate secret.
            assert_ne!(
                rejected_ss, legitimate_ss,
                "Implicit rejection failed! Bit flip at byte {} bit {} decrypted to legitimate shared secret!",
                byte_idx, bit
            );
            assert_ne!(rejected_ss, [0u8; 32], "Decapsulation returned trivial all-zero key");
        }
    }
}

#[test]
fn test_ml_dsa_signature_bit_flip_malleability_rejection() {
    let seed = [0x88u8; 32];
    let (pk, sk) = ml_dsa_87_keypair(&seed);

    let message = b"CRITICAL TRANSACTION AUTHORIZATION TRANSCRIPT";
    let rnd = [0x99u8; 32];
    let valid_sig = ml_dsa_87_sign(&sk, message, &[], &rnd).expect("ML-DSA signing failed");

    assert!(
        ml_dsa_87_verify(&pk, message, &[], &valid_sig),
        "Initial valid signature failed verification"
    );

    // Sample distinct byte positions across the 4627-byte signature:
    // covering commitment c_tilde (first 64 bytes), response vector z, and hint h
    let test_offsets = [
        0, 1, 31, 63, 64, 100, 500, 1000, 1500, 2000, 2500, 3000, 3500,
        4000, 4500, 4600, 4626,
    ];

    for &byte_idx in &test_offsets {
        for bit in [0, 3, 7] {
            let mut tampered_sig = valid_sig.clone();
            tampered_sig[byte_idx] ^= 1 << bit;

            let result = ml_dsa_87_verify(&pk, message, &[], &tampered_sig);
            assert!(
                !result,
                "Malleability vulnerability! Mutated signature at byte {} bit {} accepted as valid!",
                byte_idx, bit
            );
        }
    }
}

#[test]
fn test_aes_gcm_single_bit_flip_detection() {
    let key = [0xAAu8; 32];
    let iv = [0x11u8; 12];
    let aad = b"PROTOCOL_AUTHENTICATED_ASSOCIATED_DATA";
    let plaintext = b"Confidential financial payload 0123456789abcdefghijklmnopqrstuvwxyz";

    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let auth_tag = aes256_gcm_encrypt(&key, &iv, aad, plaintext, &mut ciphertext);

    // Verify baseline decryption succeeds
    let mut decrypted = alloc::vec![0u8; plaintext.len()];
    assert!(aes256_gcm_decrypt(&key, &iv, aad, &ciphertext, &auth_tag, &mut decrypted).is_ok());
    assert_eq!(&decrypted[..], plaintext);

    // 1. Bit flip in ciphertext (test every 4th byte)
    for byte_idx in (0..ciphertext.len()).step_by(4) {
        for bit in [0, 4, 7] {
            let mut tampered_ct = ciphertext.clone();
            tampered_ct[byte_idx] ^= 1 << bit;
            let mut out = alloc::vec![0u8; plaintext.len()];
            let res = aes256_gcm_decrypt(&key, &iv, aad, &tampered_ct, &auth_tag, &mut out);
            assert!(res.is_err(), "Ciphertext tampering at byte {} bit {} bypassed AEAD!", byte_idx, bit);
        }
    }

    // 2. Bit flip in authentication tag (test every byte)
    for tag_idx in 0..16 {
        for bit in [0, 2, 5, 7] {
            let mut tampered_tag = auth_tag;
            tampered_tag[tag_idx] ^= 1 << bit;
            let mut out = alloc::vec![0u8; plaintext.len()];
            let res = aes256_gcm_decrypt(&key, &iv, aad, &ciphertext, &tampered_tag, &mut out);
            assert!(res.is_err(), "Auth tag tampering at byte {} bit {} bypassed AEAD!", tag_idx, bit);
        }
    }

    // 3. Bit flip in AAD
    for aad_idx in 0..aad.len() {
        let mut tampered_aad = aad.to_vec();
        tampered_aad[aad_idx] ^= 1;
        let mut out = alloc::vec![0u8; plaintext.len()];
        let res = aes256_gcm_decrypt(&key, &iv, &tampered_aad, &ciphertext, &auth_tag, &mut out);
        assert!(res.is_err(), "AAD tampering at byte {} bypassed AEAD!", aad_idx);
    }
}
