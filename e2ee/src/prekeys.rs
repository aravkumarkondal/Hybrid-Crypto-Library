use alloc::vec::Vec;
use hybrid_crypto::utils::zeroize;
use hybrid_crypto::x25519::{x25519_base};
use hybrid_crypto::ml_kem::{ml_kem_768_keypair};
use crate::identity::IdentityKeyPair;
use crate::errors::E2EError;

pub struct SignedPreKeyPair {
    pub id: u32,
    pub ecc_private: [u8; 32],
    pub ecc_public: [u8; 32],
    pub pqc_private: [u8; 2400],
    pub pqc_public: [u8; 1184],
    pub signature: Vec<u8>,
}

impl Drop for SignedPreKeyPair {
    fn drop(&mut self) {
        zeroize(&mut self.ecc_private);
        zeroize(&mut self.pqc_private);
    }
}

#[derive(Clone)]
pub struct OneTimePreKeyPair {
    pub id: u32,
    pub ecc_private: [u8; 32],
    pub ecc_public: [u8; 32],
    pub pqc_private: [u8; 2400],
    pub pqc_public: [u8; 1184],
}

impl Drop for OneTimePreKeyPair {
    fn drop(&mut self) {
        zeroize(&mut self.ecc_private);
        zeroize(&mut self.pqc_private);
    }
}

#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity_key: crate::identity::IdentityPublicKey,
    pub signed_prekey_id: u32,
    pub signed_prekey_ecc_public: [u8; 32],
    pub signed_prekey_pqc_public: [u8; 1184],
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey_ecc_public: Option<[u8; 32]>,
    pub one_time_prekey_pqc_public: Option<[u8; 1184]>,
}

impl SignedPreKeyPair {
    pub fn generate(
        id: u32,
        entropy_ecc: &[u8; 32],
        entropy_pqc: &[u8; 64],
        identity_key: &IdentityKeyPair,
        sign_rnd: &[u8; 32],
    ) -> Result<Self, E2EError> {
        let ecc_public = x25519_base(entropy_ecc);
        let (pqc_public, pqc_private) = ml_kem_768_keypair(entropy_pqc);
        
        let mut data_to_sign = Vec::with_capacity(32 + 1184);
        data_to_sign.extend_from_slice(&ecc_public);
        data_to_sign.extend_from_slice(&pqc_public);

        let signature = identity_key.sign(&data_to_sign, sign_rnd)?;

        Ok(Self {
            id,
            ecc_private: *entropy_ecc,
            ecc_public,
            pqc_private,
            pqc_public,
            signature,
        })
    }
}

impl OneTimePreKeyPair {
    #[must_use]
    pub fn generate(id: u32, entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 64]) -> Self {
        let ecc_public = x25519_base(entropy_ecc);
        let (pqc_public, pqc_private) = ml_kem_768_keypair(entropy_pqc);
        
        Self {
            id,
            ecc_private: *entropy_ecc,
            ecc_public,
            pqc_private,
            pqc_public,
        }
    }
}

impl PreKeyBundle {
    pub fn verify_signature(&self) -> Result<(), E2EError> {
        let mut data_to_sign = Vec::with_capacity(32 + 1184);
        data_to_sign.extend_from_slice(&self.signed_prekey_ecc_public);
        data_to_sign.extend_from_slice(&self.signed_prekey_pqc_public);

        if self.identity_key.verify(&data_to_sign, &self.signed_prekey_signature) {
            Ok(())
        } else {
            Err(E2EError::InvalidSignature)
        }
    }
}
