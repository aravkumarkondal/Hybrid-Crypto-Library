#![cfg_attr(not(test), no_std)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::identity_op)]
#![allow(clippy::excessive_precision)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::new_without_default)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::empty_line_after_doc_comments)]
extern crate alloc;

use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidTag,
    InvalidLength,
    InvalidKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidTag => write!(f, "Decryption failed: Invalid Authentication Tag"),
            CryptoError::InvalidLength => write!(f, "Decryption failed: Invalid input length"),
            CryptoError::InvalidKey => write!(f, "Decryption failed: Invalid or weak key"),
        }
    }
}

// In a no_std environment, std::error::Error is not available unless we use the `core::error::Error` trait which is available in newer Rust versions (1.81+).
// We'll leave it as a simple enum for this zero-dependency library to maintain wide compatibility, but this improves ergonomics drastically over &'static str.


pub mod ffi;
pub mod utils;
#[cfg(feature = "x25519")]
pub mod x25519;
#[cfg(feature = "sha3")]
pub mod keccak;
#[cfg(feature = "ml-kem")]
pub mod ml_kem;
#[cfg(test)]
pub mod ntt_test;
#[cfg(feature = "ml-dsa")]
pub mod mldsa_zetas;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa_math;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa_expand;
#[cfg(feature = "ml-dsa")]
pub mod ml_dsa;
#[cfg(feature = "ml-dsa")]
pub mod signature;
#[cfg(any(feature = "sha3", feature = "hkdf"))]
pub mod sha2;
#[cfg(feature = "hkdf")]
pub mod hkdf;
#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(test)]
pub mod tests;





// ==========================================
// Layer A: Pure Rust API (Hybrid Encryption)
// ==========================================
#[cfg(feature = "hybrid")]
pub use hybrid_impl::*;

#[cfg(feature = "hybrid")]
pub mod hybrid_impl {
    use alloc::vec::Vec;
    use crate::utils::{zeroize, SecretKey};
    use crate::*;
    use crate::CryptoError;


pub struct HybridKeyPair {
    pub ecc_private: [u8; 32],
    pub ecc_public: [u8; 32],
    pub pqc_private: [u8; 2400],
    pub pqc_public: [u8; 1184],
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        zeroize(&mut self.ecc_private);
        zeroize(&mut self.pqc_private);
    }
}

pub struct EncryptedPackage {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub ecc_ephemeral_pub: [u8; 32],
    pub pqc_ciphertext: [u8; 1088],
}

impl HybridKeyPair {
    pub fn generate(entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 64]) -> Self {
        let ecc_public = x25519::x25519_base(entropy_ecc);
        let (pqc_public, pqc_private) = ml_kem::ml_kem_768_keypair(entropy_pqc);
        
        Self {
            ecc_private: *entropy_ecc,
            ecc_public,
            pqc_private,
            pqc_public,
        }
    }
}

pub fn hybrid_encrypt_payload(
    payload: &[u8],
    peer_ecc_pub: &[u8; 32],
    peer_pqc_pub: &[u8; 1184],
    entropy_ecc_ephem: &[u8; 32],
    entropy_pqc_encaps: &[u8; 32],
    iv: &[u8; 12],
) -> Result<EncryptedPackage, CryptoError> {
    // 1. Generate ephemeral ECC key
    let ecc_ephemeral_pub = x25519::x25519_base(entropy_ecc_ephem);
    let mut ecc_ss = x25519::x25519(entropy_ecc_ephem, peer_ecc_pub)?;

    // 2. Encapsulate PQC key
    let (pqc_ciphertext, mut pqc_ss) = ml_kem::ml_kem_768_encapsulate(peer_pqc_pub, entropy_pqc_encaps)?;

    // 3. Combine shared secrets using HKDF
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&ecc_ss);
    combined[32..].copy_from_slice(&pqc_ss);
    
    // Zeroize original shared secrets immediately after copying
    zeroize(&mut ecc_ss);
    zeroize(&mut pqc_ss);
    
    let mut prk = hkdf::hkdf_extract(&[], &combined);
    
    // Cryptographically bind the keys and ciphertexts into the KDF context (HPKE-style)
    // to prevent Unknown Key Share (UKS) and Identity Misbinding attacks.
    let mut info = alloc::vec::Vec::with_capacity(16 + 32 + 1184 + 32 + 1088);
    info.extend_from_slice(b"hybrid-crypto-v1");
    info.extend_from_slice(peer_ecc_pub);
    info.extend_from_slice(peer_pqc_pub);
    info.extend_from_slice(&ecc_ephemeral_pub);
    info.extend_from_slice(&pqc_ciphertext);
    
    let mut final_key = [0u8; 32];
    hkdf::hkdf_expand(&prk, &info, &mut final_key);

    // Zeroize intermediate key material
    zeroize(&mut combined);

    // 4. Encrypt payload with AES-256-GCM
    let mut ciphertext = alloc::vec![0u8; payload.len()];
    let tag = aes_gcm::aes256_gcm_encrypt(&final_key, iv, &[], payload, &mut ciphertext);
    
    // Zeroize final key and prk
    zeroize(&mut final_key);
    zeroize(&mut prk);

    Ok(EncryptedPackage {
        ciphertext,
        iv: *iv,
        tag,
        ecc_ephemeral_pub,
        pqc_ciphertext,
    })
}

/// Decrypts a Hybrid Encrypted package using the PQC ML-KEM private key and ECC private key.
/// 
/// **⚠️ SECURITY WARNING: Replay Protection**
/// This function does NOT provide replay protection or nonce tracking. While the KEM context
/// securely binds the ephemeral public keys to prevent Unknown Key Share (UKS) attacks, 
/// it is the responsibility of the calling application/protocol to ensure that the AES-GCM IV/Nonce
/// is not reused or that the `EncryptedPackage` is not blindly replayed by an adversary.
/// 
/// **⚠️ SECURITY WARNING: Unverified Plaintext Release**
/// This function verifies the AES-GCM tag in constant time *before* returning the plaintext.
/// It strictly mitigates Release of Unverified Plaintext (RUP) vulnerabilities.
pub fn hybrid_decrypt_payload(
    ciphertext: &[u8],
    iv: &[u8; 12],
    tag: &[u8; 16],
    ecc_ephemeral_pub: &[u8; 32],
    pqc_ciphertext: &[u8; 1088],
    my_ecc_priv: &[u8; 32],
    my_pqc_priv: &[u8; 2400],
) -> Result<SecretKey, CryptoError> {
    // 1. Recover ECC shared secret
    let mut ecc_ss = x25519::x25519(my_ecc_priv, ecc_ephemeral_pub)?;

    // 2. Decapsulate PQC shared secret
    let mut pqc_ss = ml_kem::ml_kem_768_decapsulate(my_pqc_priv, pqc_ciphertext);

    // 3. Combine shared secrets using HKDF
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&ecc_ss);
    combined[32..].copy_from_slice(&pqc_ss);
    
    // Zeroize original shared secrets immediately
    zeroize(&mut ecc_ss);
    zeroize(&mut pqc_ss);
    
    let mut prk = hkdf::hkdf_extract(&[], &combined);
    
    // Reconstruct the exact KDF context used by the sender for binding.
    // 1. Derive own ECC public key from private key.
    let my_ecc_pub = x25519::x25519_base(my_ecc_priv);
    // 2. Extract own PQC public key from private key (embedded at bytes 1152..2336).
    let mut my_pqc_pub = [0u8; 1184];
    my_pqc_pub.copy_from_slice(&my_pqc_priv[1152..2336]);
    
    let mut info = alloc::vec::Vec::with_capacity(16 + 32 + 1184 + 32 + 1088);
    info.extend_from_slice(b"hybrid-crypto-v1");
    info.extend_from_slice(&my_ecc_pub);
    info.extend_from_slice(&my_pqc_pub);
    info.extend_from_slice(ecc_ephemeral_pub);
    info.extend_from_slice(pqc_ciphertext);
    
    let mut final_key = [0u8; 32];
    hkdf::hkdf_expand(&prk, &info, &mut final_key);
    
    // Zeroize intermediate key material
    zeroize(&mut combined);

    // 4. Decrypt payload with AES-256-GCM
    let mut plaintext = SecretKey(alloc::vec![0u8; ciphertext.len()]);
    let result = aes_gcm::aes256_gcm_decrypt(
        &final_key, 
        iv, 
        &[], 
        ciphertext, 
        tag,
        &mut plaintext
    );
    
    // Zeroize final key and prk
    zeroize(&mut final_key);
    zeroize(&mut prk);
    
    match result {
        Ok(_) => Ok(plaintext),
        Err(_) => Err(CryptoError::InvalidTag)
    }
}


}
