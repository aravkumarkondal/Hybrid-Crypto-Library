#![cfg(any(target_os = "macos", target_os = "ios"))]

extern crate alloc;

use alloc::vec::Vec;
use e2ee::keystore::SecureKeyStore;
use e2ee::errors::E2EError;
use e2ee::identity::{SoftwareIdentityKeyPair, IdentityPublicKey};

pub struct AppleSecureEnclaveStore {
    ecc_public: [u8; 32],
    pqc_public: Vec<u8>,
    key_tag: alloc::string::String,
}

impl AppleSecureEnclaveStore {
    pub fn new(ecc_public: [u8; 32], pqc_public: Vec<u8>, key_tag: alloc::string::String) -> Self {
        Self {
            ecc_public,
            pqc_public,
            key_tag,
        }
    }

    /// Generates a new software identity keypair and seals its private keys into the macOS/iOS Keychain.
    pub fn generate_and_seal(
        key_tag: &str,
        entropy_ecc: &[u8; 32],
        entropy_pqc: &[u8; 32]
    ) -> Result<Self, E2EError> {
        let sw_key = SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc);
        
        let mut blob = Vec::new();
        blob.extend_from_slice(&sw_key.ecc_private);
        blob.extend_from_slice(sw_key.pqc_private.as_slice());

        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use keyring::Entry;

        let b64 = STANDARD.encode(&blob);
        let entry = Entry::new("splendid_mendeleev_keystore", key_tag).map_err(|_| E2EError::DoubleRatchetError)?;
        
        if entry.set_password(&b64).is_err() {
            hybrid_crypto::utils::zeroize(&mut blob);
            return Err(E2EError::DoubleRatchetError);
        }
        
        hybrid_crypto::utils::zeroize(&mut blob);

        Ok(Self::new(sw_key.ecc_public, sw_key.pqc_public.clone(), alloc::string::String::from(key_tag)))
    }

    fn retrieve_blob(&self) -> Result<hybrid_crypto::utils::SecretKey, E2EError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use keyring::Entry;

        if let Ok(entry) = Entry::new("splendid_mendeleev_keystore", &self.key_tag) {
            if let Ok(password) = entry.get_password() {
                if let Ok(blob) = STANDARD.decode(&password) {
                    return Ok(hybrid_crypto::utils::SecretKey(blob));
                }
            }
        }
        Err(E2EError::InvalidSignature)
    }

    
    fn unseal_software_key(&self) -> Result<SoftwareIdentityKeyPair, E2EError> {
        let mut blob = self.retrieve_blob()?;
        if blob.0.len() < 32 {
            return Err(E2EError::InvalidSignature);
        }
        
        let mut ecc_private = [0u8; 32];
        ecc_private.copy_from_slice(&blob.0[0..32]);
        
        let mut pqc_private_vec = alloc::vec![0u8; blob.0.len() - 32];
        pqc_private_vec.copy_from_slice(&blob.0[32..]);
        let pqc_private = hybrid_crypto::utils::SecretKey(pqc_private_vec);
        
        // Zeroize the intermediate unsealed blob explicitly, even though SecretKey drops zeroize.
        hybrid_crypto::utils::zeroize(&mut blob.0);
        
        Ok(SoftwareIdentityKeyPair {
            ecc_private,
            ecc_public: self.ecc_public,
            pqc_private,
            pqc_public: self.pqc_public.clone(),
        })
    }
}

impl SecureKeyStore for AppleSecureEnclaveStore {
    fn public_key(&self) -> Result<IdentityPublicKey, E2EError> {
        Ok(IdentityPublicKey {
            ecc_public: self.ecc_public,
            pqc_public: self.pqc_public.clone(),
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError> {
        // Unseal the key purely into hardened RAM for the duration of the signature.
        let sw_key = self.unseal_software_key()?;
        let sig = hybrid_crypto::ml_dsa::ml_dsa_87_sign(&sw_key.pqc_private, data, &[], rnd)
            .map_err(|_| E2EError::SigningError);
        // sw_key is zeroized on Drop
        sig
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError> {
        let sw_key = self.unseal_software_key()?;
        hybrid_crypto::x25519::x25519(&sw_key.ecc_private, peer_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)
    }
}
