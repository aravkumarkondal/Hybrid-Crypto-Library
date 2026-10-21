#![cfg(target_os = "linux")]

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

pub struct LinuxSoftwareKeystore {
    ecc_public: [u8; 32],
    pqc_public: Vec<u8>,
    key_tag: alloc::string::String,
}

impl LinuxSoftwareKeystore {
    pub fn new(ecc_public: [u8; 32], pqc_public: Vec<u8>, key_tag: alloc::string::String) -> Self {
        Self {
            ecc_public,
            pqc_public,
            key_tag,
        }
    }

    /// Generates a new software identity keypair, wraps private keys with an AES-256-GCM
    /// Key Encryption Key (KEK), and seals both into the Linux Secret Service (GNOME Keyring/KWallet).
    ///
    /// Storage layout in Secret Service:
    ///   item label `{key_tag}_kek`    → 32-byte random AES-256 KEK
    ///   item label `{key_tag}_sealed` → IV (12) || AES-256-GCM(KEK, IV, raw_blob) (4928) || tag (16)
    ///
    /// `key_tag` is used as AEAD Associated Data (AAD), binding the sealed blob to this key identity.
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

        use secret_service::{SecretService, EncryptionType};
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|_| E2EError::DoubleRatchetError)?;
        let collection = ss.get_any_collection().map_err(|_| E2EError::DoubleRatchetError)?;

        // Store the KEK in Secret Service (encrypted via D-Bus session DH exchange)
        let kek_label = alloc::format!("{}_kek", key_tag);
        collection.create_item(
            &kek_label,
            std::collections::HashMap::new(),
            kek_entropy,
            true,
            "application/octet-stream",
        ).map_err(|_| E2EError::DoubleRatchetError)?;

        // Store the AES-256-GCM sealed blob in Secret Service
        let sealed_label = alloc::format!("{}_sealed", key_tag);
        if let Err(_) = collection.create_item(
            &sealed_label,
            std::collections::HashMap::new(),
            &sealed,
            true,
            "application/octet-stream",
        ) {
            zeroize(&mut sealed);
            return Err(E2EError::DoubleRatchetError);
        }

        zeroize(&mut sealed);

        Ok(Self::new(sw_key.ecc_public, sw_key.pqc_public.clone(), alloc::string::String::from(key_tag)))
    }

    /// Find a Secret Service item by label and return its secret bytes.
    fn retrieve_secret_by_label(&self, label: &str) -> Result<Vec<u8>, E2EError> {
        use secret_service::{SecretService, EncryptionType};
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|_| E2EError::InvalidSignature)?;
        let collection = ss.get_any_collection().map_err(|_| E2EError::InvalidSignature)?;

        let search_results = collection
            .search_items(std::collections::HashMap::new())
            .map_err(|_| E2EError::InvalidSignature)?;

        for item in search_results {
            if let Ok(item_label) = item.get_label() {
                if item_label == label {
                    return item.get_secret().map_err(|_| E2EError::InvalidSignature);
                }
            }
        }

        Err(E2EError::InvalidSignature)
    }

    /// Retrieves the AES-256-GCM KEK from Secret Service and decrypts the sealed private key blob.
    fn unseal_software_key(&self) -> Result<SoftwareIdentityKeyPair, E2EError> {
        // 1. Load KEK from Secret Service
        let kek_label = alloc::format!("{}_kek", self.key_tag);
        let kek_bytes = self.retrieve_secret_by_label(&kek_label)?;
        if kek_bytes.len() != 32 {
            return Err(E2EError::InvalidSignature);
        }
        let mut kek = hybrid_crypto::utils::ZeroizingArray::new([0u8; 32]);
        kek.copy_from_slice(&kek_bytes);

        // 2. Load sealed blob from Secret Service
        let sealed_label = alloc::format!("{}_sealed", self.key_tag);
        let sealed = self.retrieve_secret_by_label(&sealed_label)?;
        if sealed.len() != SEALED_BLOB_LEN {
            return Err(E2EError::InvalidSignature);
        }

        // 3. Parse sealed blob: IV || ciphertext || tag
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&sealed[..12]);
        let ciphertext = &sealed[12..12 + RAW_BLOB_LEN];
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&sealed[12 + RAW_BLOB_LEN..]);

        // 4. AES-256-GCM decrypt; AAD = key_tag bytes
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

impl SecureKeyStore for LinuxSoftwareKeystore {
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
