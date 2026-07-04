use alloc::vec::Vec;
use hybrid_crypto::utils::{zeroize, SecretKey};
use hybrid_crypto::x25519::{x25519_base};
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_verify};

pub struct IdentityKeyPair {
    pub ecc_private: [u8; 32],
    pub ecc_public: [u8; 32],
    pub pqc_private: SecretKey, // ML-DSA-87 private key is large, use SecretKey
    pub pqc_public: Vec<u8>,
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        zeroize(&mut self.ecc_private);
    }
}

#[derive(Clone, Debug)]
pub struct IdentityPublicKey {
    pub ecc_public: [u8; 32],
    pub pqc_public: Vec<u8>,
}

impl IdentityKeyPair {
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

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            ecc_public: self.ecc_public,
            pqc_public: self.pqc_public.clone(),
        }
    }

    pub fn sign(&self, message: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, hybrid_crypto::CryptoError> {
        hybrid_crypto::ml_dsa::ml_dsa_87_sign(&self.pqc_private, message, &[], rnd)
    }
}

impl IdentityPublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        ml_dsa_87_verify(&self.pqc_public, message, &[], signature)
    }
}
