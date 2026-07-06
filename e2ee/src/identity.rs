use alloc::vec::Vec;
use hybrid_crypto::utils::{zeroize, SecretKey};
use hybrid_crypto::x25519::{x25519_base};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_verify};

use crate::keystore::SecureKeyStore;
use crate::errors::E2EError;
use alloc::boxed::Box;

pub struct SoftwareIdentityKeyPair {
    pub ecc_private: [u8; 32],
    pub ecc_public: [u8; 32],
    pub pqc_private: SecretKey,
    pub pqc_public: Vec<u8>,
}

/// The Identity Key Pair for an E2EE Session.
/// 
/// This enum supports two modes:
/// * `Software`: The X25519 and ML-DSA keys reside continuously in RAM and are zeroized on drop.
/// * `Hardware`: The keys are backed by a `SecureKeyStore`. X25519 keys may remain hardware-resident, 
///   while ML-DSA keys are sealed in hardware and temporarily unsealed into RAM only during a signing operation.
pub enum IdentityKeyPair {
    Software(SoftwareIdentityKeyPair),
    Hardware(Box<dyn SecureKeyStore>),
}

impl Drop for SoftwareIdentityKeyPair {
    fn drop(&mut self) {
        zeroize(&mut self.ecc_private);
    }
}

#[derive(Clone, Debug)]
pub struct IdentityPublicKey {
    pub ecc_public: [u8; 32],
    pub pqc_public: Vec<u8>,
}

impl SoftwareIdentityKeyPair {
    #[must_use]
    pub fn generate(entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 32]) -> Self {
        let ecc_public = x25519_base(entropy_ecc);
        let (pqc_public, pqc_private) = ml_dsa_87_keypair(entropy_pqc);
        
        Self {
            ecc_private: *entropy_ecc,
            ecc_public,
            pqc_private,
            pqc_public,
        }
    }
}

impl IdentityKeyPair {
    #[must_use]
    pub fn generate(entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 32]) -> Self {
        Self::Software(SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc))
    }
    
    #[must_use]
    pub fn from_hardware(store: Box<dyn SecureKeyStore>) -> Self {
        Self::Hardware(store)
    }

    pub const fn ecc_private_bytes(&self) -> Result<&[u8; 32], E2EError> {
        match self {
            Self::Software(s) => Ok(&s.ecc_private),
            Self::Hardware(_) => Err(E2EError::InvalidSignature), // Refactor DH calls to not use this
        }
    }

    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        match self {
            Self::Software(s) => IdentityPublicKey {
                ecc_public: s.ecc_public,
                pqc_public: s.pqc_public.clone(),
            },
            Self::Hardware(h) => h.public_key().expect("Failed to get public key from hardware"),
        }
    }

    pub fn sign(&self, message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError> {
        match self {
            Self::Software(s) => hybrid_crypto::ml_dsa::ml_dsa_87_sign(&s.pqc_private, message, &[], rnd)
                .map_err(|_| E2EError::SigningError),
            Self::Hardware(h) => h.sign_payload(message, rnd),
        }
    }

    pub fn ecdh(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError> {
        match self {
            Self::Software(s) => hybrid_crypto::x25519::x25519(&s.ecc_private, peer_public)
                .map_err(|_| E2EError::InvalidPreKeyBundle),
            Self::Hardware(h) => h.shared_secret(peer_public),
        }
    }
}

impl IdentityPublicKey {
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        ml_dsa_87_verify(&self.pqc_public, message, &[], signature)
    }
}
