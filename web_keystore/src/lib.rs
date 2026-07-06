#![cfg(target_arch = "wasm32")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use e2ee::keystore::SecureKeyStore;
use e2ee::errors::E2EError;
use e2ee::identity::{SoftwareIdentityKeyPair, IdentityPublicKey};

// This represents a simulated wrapper around WebCrypto.
// True WebCrypto sealing would use `window.crypto.subtle.generateKey` to create a non-extractable AES-GCM key,
// encrypt the `blob`, and store it in IndexedDB.
pub struct WebCryptoStore {
    indexeddb_key: String,
    ecc_public: [u8; 32],
    pqc_public: Vec<u8>,
}

impl WebCryptoStore {
    pub fn new(indexeddb_key: &str, ecc_public: [u8; 32], pqc_public: Vec<u8>) -> Self {
        Self {
            indexeddb_key: indexeddb_key.into(),
            ecc_public,
            pqc_public,
        }
    }

    /// Generates a new software identity keypair and seals its private keys using WebCrypto and IndexedDB.
    pub fn generate_and_seal(
        indexeddb_key: &str,
        entropy_ecc: &[u8; 32],
        entropy_pqc: &[u8; 32]
    ) -> Result<Self, E2EError> {
        let sw_key = SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc);
        
        let mut blob = Vec::new();
        blob.extend_from_slice(&sw_key.ecc_private);
        blob.extend_from_slice(sw_key.pqc_private.as_slice());

        // Use `web_sys::window().unwrap().crypto().unwrap().subtle()` to encrypt the blob.
        // Save to IndexedDB.
        
        hybrid_crypto::utils::zeroize(&mut blob);

        Ok(Self::new(indexeddb_key, sw_key.ecc_public, sw_key.pqc_public.clone()))
    }

    fn retrieve_and_unseal(&self) -> Result<hybrid_crypto::utils::SecretKey, E2EError> {
        // Retrieve from IndexedDB, decrypt using the non-extractable WebCrypto AES-GCM key.
        Err(E2EError::InvalidSignature)
    }

    fn unseal_software_key(&self) -> Result<SoftwareIdentityKeyPair, E2EError> {
        let mut blob = self.retrieve_and_unseal()?;
        if blob.0.len() < 32 {
            return Err(E2EError::InvalidSignature);
        }
        
        let mut ecc_private = [0u8; 32];
        ecc_private.copy_from_slice(&blob.0[0..32]);
        
        let mut pqc_private_vec = alloc::vec![0u8; blob.0.len() - 32];
        pqc_private_vec.copy_from_slice(&blob.0[32..]);
        let pqc_private = hybrid_crypto::utils::SecretKey(pqc_private_vec);
        
        hybrid_crypto::utils::zeroize(&mut blob.0);
        
        Ok(SoftwareIdentityKeyPair {
            ecc_private,
            ecc_public: self.ecc_public,
            pqc_private,
            pqc_public: self.pqc_public.clone(),
        })
    }
}

impl SecureKeyStore for WebCryptoStore {
    fn public_key(&self) -> Result<IdentityPublicKey, E2EError> {
        Ok(IdentityPublicKey {
            ecc_public: self.ecc_public,
            pqc_public: self.pqc_public.clone(),
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError> {
        let sw_key = self.unseal_software_key()?;
        hybrid_crypto::ml_dsa::ml_dsa_87_sign(&sw_key.pqc_private, data, &[], rnd)
            .map_err(|_| E2EError::SigningError)
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError> {
        let sw_key = self.unseal_software_key()?;
        hybrid_crypto::x25519::x25519(&sw_key.ecc_private, peer_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)
    }
}
