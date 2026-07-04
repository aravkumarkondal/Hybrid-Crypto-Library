use alloc::vec::Vec;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use crate::errors::E2EError;

#[derive(Clone, Debug)]
pub struct MessageHeader {
    pub dh_public: [u8; 32],
    pub kem_public: [u8; 1184],
    pub kem_ciphertext: [u8; 1088],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

impl Message {
    pub fn encrypt(
        key: &[u8; 32],
        iv: &[u8; 12],
        header: MessageHeader,
        plaintext: &[u8],
    ) -> Self {
        // Associated Data is the serialized header
        let mut ad = Vec::with_capacity(32 + 1184 + 1088 + 4 + 4);
        ad.extend_from_slice(&header.dh_public);
        ad.extend_from_slice(&header.kem_public);
        ad.extend_from_slice(&header.kem_ciphertext);
        ad.extend_from_slice(&header.previous_chain_length.to_le_bytes());
        ad.extend_from_slice(&header.message_number.to_le_bytes());

        let mut ciphertext = alloc::vec![0u8; plaintext.len()];
        let auth_tag = aes256_gcm_encrypt(key, iv, &ad, plaintext, &mut ciphertext);

        Self {
            header,
            ciphertext,
            auth_tag,
        }
    }

    pub fn decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
    ) -> Result<Vec<u8>, E2EError> {
        let mut ad = Vec::with_capacity(32 + 1184 + 1088 + 4 + 4);
        ad.extend_from_slice(&self.header.dh_public);
        ad.extend_from_slice(&self.header.kem_public);
        ad.extend_from_slice(&self.header.kem_ciphertext);
        ad.extend_from_slice(&self.header.previous_chain_length.to_le_bytes());
        ad.extend_from_slice(&self.header.message_number.to_le_bytes());

        let mut plaintext = hybrid_crypto::utils::SecretKey(alloc::vec![0u8; self.ciphertext.len()]);
        
        aes256_gcm_decrypt(
            key,
            iv,
            &ad,
            &self.ciphertext,
            &self.auth_tag,
            &mut plaintext,
        ).map_err(|_| E2EError::MessageDecryptionFailed)?;

        Ok(plaintext.0.clone())
    }
}

pub struct PreKeyMessage {
    pub prekey_id: Option<u32>,
    pub signed_prekey_id: u32,
    pub initiator_identity_ecc_public: [u8; 32],
    pub initiator_identity_pqc_public: Vec<u8>,
    pub initiator_ephemeral_ecc_public: [u8; 32],
    pub pqc_ciphertext_spk: [u8; 1088],
    pub pqc_ciphertext_opk: Option<[u8; 1088]>,
    pub initial_message: Message,
}
