#![cfg(any(target_os = "macos", target_os = "ios"))]

extern crate alloc;

use alloc::vec::Vec;
use e2ee::keystore::SecureKeyStore;
use e2ee::errors::E2EError;
use e2ee::identity::{SoftwareIdentityKeyPair, IdentityPublicKey};
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::utils::zeroize;

/// AES-256-GCM sealed blob layout:
///   [ IV (12 bytes) | ciphertext (4928 bytes) | auth_tag (16 bytes) ]
/// Total: 4956 bytes
const RAW_BLOB_LEN: usize = 32 + 4896;        // ECC private (32) + ML-DSA-87 private (4896)
const SEALED_BLOB_LEN: usize = 12 + RAW_BLOB_LEN + 16; // IV + plaintext + AES-GCM tag

pub struct AppleSoftwareKeystore {
    ecc_public: [u8; 32],
    pqc_public: Vec<u8>,
    key_tag: alloc::string::String,
}

impl AppleSoftwareKeystore {
    pub fn new(ecc_public: [u8; 32], pqc_public: Vec<u8>, key_tag: alloc::string::String) -> Self {
        Self {
            ecc_public,
            pqc_public,
            key_tag,
        }
    }

    /// Generates a new software identity keypair, wraps private keys with an AES-256-GCM
    /// Key Encryption Key (KEK), and seals both into the macOS/iOS Keychain.
    ///
    /// Storage layout in Keychain:
    ///   `{key_tag}_kek`    → 32-byte random AES-256 KEK
    ///   `{key_tag}_sealed` → IV (12) || AES-256-GCM(KEK, IV, raw_blob) (4928) || tag (16)
    ///
    /// `key_tag` is used as AEAD Associated Data (AAD) to bind the sealed blob to this key identity,
    /// preventing a sealed blob from one key being substituted for another.
    pub fn generate_and_seal(
        key_tag: &str,
        entropy_ecc: &[u8; 32],
        entropy_pqc: &[u8; 32],
        kek_entropy: &[u8; 32],
        iv_entropy: &[u8; 12],
    ) -> Result<Self, E2EError> {
        let sw_key = SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc);

        // Build raw private key blob: ECC || PQC
        let mut raw = hybrid_crypto::utils::ZeroizingArray::new([0u8; RAW_BLOB_LEN]);
        raw[..32].copy_from_slice(&sw_key.ecc_private);
        raw[32..].copy_from_slice(sw_key.pqc_private.as_slice());

        // AES-256-GCM encrypt the raw blob using the KEK
        // AAD = key_tag bytes, binding the ciphertext to this specific key identity
        let mut ciphertext = alloc::vec![0u8; RAW_BLOB_LEN];
        let auth_tag = aes256_gcm_encrypt(kek_entropy, iv_entropy, key_tag.as_bytes(), &*raw, &mut ciphertext);

        // Build sealed blob: IV || ciphertext || tag
        let mut sealed = Vec::with_capacity(SEALED_BLOB_LEN);
        sealed.extend_from_slice(iv_entropy);
        sealed.extend_from_slice(&ciphertext);
        sealed.extend_from_slice(&auth_tag);
        zeroize(&mut ciphertext);

        use security_framework::passwords::set_generic_password;

        // Store the KEK in Keychain (hardware-protected by Keychain Services / Secure Enclave)
        let kek_tag = alloc::format!("{}_kek", key_tag);
        if set_generic_password("splendid_mendeleev_keystore", &kek_tag, kek_entropy).is_err() {
            zeroize(&mut sealed);
            return Err(E2EError::DoubleRatchetError);
        }

        // Store the AES-256-GCM sealed blob in Keychain
        let sealed_tag = alloc::format!("{}_sealed", key_tag);
        if set_generic_password("splendid_mendeleev_keystore", &sealed_tag, &sealed).is_err() {
            zeroize(&mut sealed);
            return Err(E2EError::DoubleRatchetError);
        }

        zeroize(&mut sealed);

        Ok(Self::new(sw_key.ecc_public, sw_key.pqc_public.clone(), alloc::string::String::from(key_tag)))
    }

    /// Retrieves the AES-256-GCM KEK from Keychain and decrypts the sealed private key blob.
    fn unseal_software_key(&self) -> Result<SoftwareIdentityKeyPair, E2EError> {
        use security_framework::passwords::get_generic_password;

        // 1. Load KEK from Keychain (hardware-protected)
        let kek_tag = alloc::format!("{}_kek", self.key_tag);
        let kek_bytes = get_generic_password("splendid_mendeleev_keystore", &kek_tag)
            .map_err(|_| E2EError::InvalidSignature)?;
        if kek_bytes.len() != 32 {
            return Err(E2EError::InvalidSignature);
        }
        let mut kek = hybrid_crypto::utils::ZeroizingArray::new([0u8; 32]);
        kek.copy_from_slice(&kek_bytes);

        // 2. Load sealed blob from Keychain
        let sealed_tag = alloc::format!("{}_sealed", self.key_tag);
        let sealed = get_generic_password("splendid_mendeleev_keystore", &sealed_tag)
            .map_err(|_| E2EError::InvalidSignature)?;
        if sealed.len() != SEALED_BLOB_LEN {
            return Err(E2EError::InvalidSignature);
        }

        // 3. Parse sealed blob: IV || ciphertext || tag
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&sealed[..12]);

        let ciphertext = &sealed[12..12 + RAW_BLOB_LEN];

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&sealed[12 + RAW_BLOB_LEN..]);

        // 4. AES-256-GCM decrypt; AAD = key_tag bytes (must match what was used during sealing)
        let mut raw = hybrid_crypto::utils::ZeroizingArray::new([0u8; RAW_BLOB_LEN]);
        aes256_gcm_decrypt(&*kek, &iv, self.key_tag.as_bytes(), ciphertext, &auth_tag, &mut *raw)
            .map_err(|_| E2EError::DecryptionError)?;

        // 5. Split into ECC and PQC keys
        let mut ecc_private = [0u8; 32];
        ecc_private.copy_from_slice(&raw[..32]);

        let mut pqc_private_vec = alloc::vec![0u8; 4896];
        pqc_private_vec.copy_from_slice(&raw[32..]);
        let pqc_private = hybrid_crypto::utils::SecretKey(pqc_private_vec);

        // raw is zeroized on drop via ZeroizingArray

        Ok(SoftwareIdentityKeyPair {
            ecc_private,
            ecc_public: self.ecc_public,
            pqc_private,
            pqc_public: self.pqc_public.clone(),
        })
    }
}

impl SecureKeyStore for AppleSoftwareKeystore {
    fn public_key(&self) -> e2ee::keystore::BoxFuture<'_, Result<IdentityPublicKey, E2EError>> {
        let ecc_public = self.ecc_public;
        let pqc_public = self.pqc_public.clone();
        alloc::boxed::Box::pin(async move {
            Ok(IdentityPublicKey {
                ecc_public,
                pqc_public,
            })
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> e2ee::keystore::BoxFuture<'_, Result<Vec<u8>, E2EError>> {
        let data_vec = data.to_vec();
        let rnd_arr = *rnd;
        alloc::boxed::Box::pin(async move {
            let sw_key = self.unseal_software_key()?;
            let sig = hybrid_crypto::ml_dsa::ml_dsa_87_sign(&sw_key.pqc_private, &data_vec, &[], &rnd_arr)
                .map_err(|_| E2EError::SigningError)?;
            Ok(sig)
        })
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> e2ee::keystore::BoxFuture<'_, Result<[u8; 32], E2EError>> {
        let peer_pub = *peer_public;
        alloc::boxed::Box::pin(async move {
            let sw_key = self.unseal_software_key()?;
            hybrid_crypto::x25519::x25519(&sw_key.ecc_private, &peer_pub)
                .map_err(|_| E2EError::InvalidPreKeyBundle)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_kek_blob_sizing() {
        let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
        assert_eq!(sw_key.ecc_private.len(), 32);
        assert_eq!(sw_key.pqc_private.as_slice().len(), 4896);

        // RAW_BLOB_LEN = 32 + 4896 = 4928
        assert_eq!(RAW_BLOB_LEN, 4928);
        // SEALED_BLOB_LEN = IV(12) + 4928 + tag(16) = 4956
        assert_eq!(SEALED_BLOB_LEN, 4956);
    }

    #[test]
    fn test_aes256_kek_seal_unseal_roundtrip() {
        // Test the AES-256-GCM envelope encryption directly (without Keychain I/O)
        use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
        use hybrid_crypto::utils::zeroize;

        let sw_key = SoftwareIdentityKeyPair::generate(&[3; 32], &[4; 32]);
        let mut raw = [0u8; RAW_BLOB_LEN];
        raw[..32].copy_from_slice(&sw_key.ecc_private);
        raw[32..].copy_from_slice(sw_key.pqc_private.as_slice());

        let kek = [0xABu8; 32];
        let iv  = [0x12u8; 12];
        let aad = b"test_key_tag";

        // Seal
        let mut ciphertext = alloc::vec![0u8; RAW_BLOB_LEN];
        let auth_tag = aes256_gcm_encrypt(&kek, &iv, aad, &raw, &mut ciphertext);

        // Verify sealed blob length
        let mut sealed = alloc::vec![0u8; SEALED_BLOB_LEN];
        sealed[..12].copy_from_slice(&iv);
        sealed[12..12 + RAW_BLOB_LEN].copy_from_slice(&ciphertext);
        sealed[12 + RAW_BLOB_LEN..].copy_from_slice(&auth_tag);
        assert_eq!(sealed.len(), SEALED_BLOB_LEN);

        // Unseal
        let iv_r = <[u8; 12]>::try_from(&sealed[..12]).unwrap();
        let ct_r = &sealed[12..12 + RAW_BLOB_LEN];
        let tag_r = <[u8; 16]>::try_from(&sealed[12 + RAW_BLOB_LEN..]).unwrap();
        let mut recovered = [0u8; RAW_BLOB_LEN];
        aes256_gcm_decrypt(&kek, &iv_r, aad, ct_r, &tag_r, &mut recovered).unwrap();

        // Verify round-trip
        assert_eq!(&recovered[..32], &sw_key.ecc_private);
        assert_eq!(&recovered[32..], sw_key.pqc_private.as_slice());

        // Verify tamper detection: mutate auth tag byte, expect AEAD failure
        // Clone the ciphertext so we can re-borrow independently from the sealed vec mutation
        let ct_clone = sealed[12..12 + RAW_BLOB_LEN].to_vec();
        sealed[12 + RAW_BLOB_LEN] ^= 0xFF;
        let tag_bad = <[u8; 16]>::try_from(&sealed[12 + RAW_BLOB_LEN..]).unwrap();
        let mut bogus = [0u8; RAW_BLOB_LEN];
        assert!(aes256_gcm_decrypt(&kek, &iv_r, aad, &ct_clone, &tag_bad, &mut bogus).is_err());

        zeroize(&mut raw);
        zeroize(&mut recovered);
    }
}

