use alloc::vec::Vec;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use crate::errors::E2EError;
use crate::session::MultiDeviceSession;
use crate::serialization::Serialize;

pub struct SessionBackup {
    pub ciphertext: Vec<u8>,
    pub iv: [u8; 12],
    pub auth_tag: [u8; 16],
}

impl SessionBackup {
    /// Creates a forward-secure backup of the multi-device session.
    /// The backup key is assumed to be a strong 256-bit key (e.g. Argon2id derived from a passphrase).
    /// The caller must provide a cryptographically secure random 12-byte IV.
    pub fn create(session: &MultiDeviceSession, backup_key: &[u8; 32], iv: &[u8; 12]) -> Result<Self, E2EError> {
        let plaintext = session.serialize();
        
        let mut ciphertext = alloc::vec![0u8; plaintext.len()];
        let auth_tag = aes256_gcm_encrypt(backup_key, iv, b"E2EE_BACKUP_V1", &plaintext, &mut ciphertext);
        
        Ok(Self {
            ciphertext,
            iv: *iv,
            auth_tag,
        })
    }

    /// Restores a multi-device session from a backup.
    pub fn restore(&self, backup_key: &[u8; 32]) -> Result<MultiDeviceSession, E2EError> {
        let mut plaintext_container = hybrid_crypto::utils::SecretKey(alloc::vec![0u8; self.ciphertext.len()]);
        
        aes256_gcm_decrypt(
            backup_key,
            &self.iv,
            b"E2EE_BACKUP_V1",
            &self.ciphertext,
            &self.auth_tag,
            &mut plaintext_container,
        ).map_err(|_| E2EError::BackupFailed)?;

        let session = MultiDeviceSession::deserialize(&plaintext_container)?;
        Ok(session)
    }
}
