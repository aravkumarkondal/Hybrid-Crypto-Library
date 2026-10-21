use alloc::vec;
use alloc::vec::Vec;
use hybrid_crypto::hkdf::hkdf_expand;
use hybrid_crypto::utils::zeroize;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use crate::errors::E2EError;
use crate::identity::{IdentityKeyPair, IdentityPublicKey};
use crate::serialization::Serialize;

#[derive(Clone)]
pub struct SenderKeyChain {
    pub chain_key: [u8; 32],
    pub iteration: u32,
}

impl Drop for SenderKeyChain {
    fn drop(&mut self) {
        zeroize(&mut self.chain_key);
    }
}

impl SenderKeyChain {
    #[must_use]
    pub const fn new(seed: &[u8; 32], iteration: u32) -> Self {
        Self {
            chain_key: *seed,
            iteration,
        }
    }

    pub fn next_message_key(&mut self) -> ([u8; 32], [u8; 12]) {
        let mut msg_key = [0u8; 32];
        hkdf_expand(&self.chain_key, b"MessageKey", &mut msg_key);

        let mut iv = [0u8; 12];
        hkdf_expand(&self.chain_key, b"IV", &mut iv);

        let mut next_chain = [0u8; 32];
        hkdf_expand(&self.chain_key, b"NextChain", &mut next_chain);

        self.chain_key = next_chain;
        self.iteration += 1;

        (msg_key, iv)
    }
}

#[derive(Clone, Debug)]
pub struct SenderKeyDistributionMessage {
    pub group_id: [u8; 32],
    pub sender_identity: IdentityPublicKey,
    pub chain_id: u32,
    pub iteration: u32,
    pub chain_key: [u8; 32],
}

impl Serialize for SenderKeyDistributionMessage {
    fn serialize(&self) -> Vec<u8> {
        let id_bytes = self.sender_identity.serialize();
        let mut buf = Vec::with_capacity(32 + 4 + id_bytes.len() + 4 + 4 + 32);
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.iteration.to_le_bytes());
        buf.extend_from_slice(&self.chain_key);
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut offset = 0;
        if data.len() < 32 + 4 { return Err(E2EError::InvalidMessageFormat); }
        
        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut id_len_bytes = [0u8; 4];
        id_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let id_len = u32::from_le_bytes(id_len_bytes) as usize;
        offset += 4;

        if data.len().saturating_sub(offset) < id_len + 4 + 4 + 32 {
            return Err(E2EError::InvalidMessageFormat);
        }

        let sender_identity = IdentityPublicKey::deserialize(&data[offset..offset+id_len])?;
        offset += id_len;

        let mut b = [0u8; 4];
        b.copy_from_slice(&data[offset..offset+4]);
        let chain_id = u32::from_le_bytes(b);
        offset += 4;

        b.copy_from_slice(&data[offset..offset+4]);
        let iteration = u32::from_le_bytes(b);
        offset += 4;

        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&data[offset..offset+32]);
        
        Ok(Self {
            group_id,
            sender_identity,
            chain_id,
            iteration,
            chain_key,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SenderKeyMessage {
    pub group_id: [u8; 32],
    pub sender_identity: IdentityPublicKey,
    pub chain_id: u32,
    pub iteration: u32,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
    pub signature: Vec<u8>,
}

impl Serialize for SenderKeyMessage {
    fn serialize(&self) -> Vec<u8> {
        let id_bytes = self.sender_identity.serialize();
        let capacity = 32 + 4 + id_bytes.len() + 4 + 4 + 4 + self.ciphertext.len() + 16 + 4 + self.signature.len();
        let mut buf = Vec::with_capacity(capacity);
        
        buf.extend_from_slice(&self.group_id);
        buf.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_bytes);

        buf.extend_from_slice(&self.chain_id.to_le_bytes());
        buf.extend_from_slice(&self.iteration.to_le_bytes());

        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);

        buf.extend_from_slice(&self.auth_tag);

        buf.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.signature);

        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut offset = 0;
        if data.len() < 32 + 4 { return Err(E2EError::InvalidMessageFormat); }

        let mut group_id = [0u8; 32];
        group_id.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut id_len_bytes = [0u8; 4];
        id_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let id_len = u32::from_le_bytes(id_len_bytes) as usize;
        offset += 4;

        if data.len().saturating_sub(offset) < id_len + 4 + 4 + 4 {
            return Err(E2EError::InvalidMessageFormat);
        }

        let sender_identity = IdentityPublicKey::deserialize(&data[offset..offset+id_len])?;
        offset += id_len;

        let mut b = [0u8; 4];
        b.copy_from_slice(&data[offset..offset+4]);
        let chain_id = u32::from_le_bytes(b);
        offset += 4;

        b.copy_from_slice(&data[offset..offset+4]);
        let iteration = u32::from_le_bytes(b);
        offset += 4;

        let mut ct_len_bytes = [0u8; 4];
        ct_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;
        offset += 4;

        if data.len().saturating_sub(offset) < ct_len + 16 + 4 {
            return Err(E2EError::InvalidMessageFormat);
        }

        let ciphertext = data[offset..offset+ct_len].to_vec();
        offset += ct_len;

        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&data[offset..offset+16]);
        offset += 16;

        let mut sig_len_bytes = [0u8; 4];
        sig_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let sig_len = u32::from_le_bytes(sig_len_bytes) as usize;
        offset += 4;

        if data.len().saturating_sub(offset) < sig_len {
            return Err(E2EError::InvalidMessageFormat);
        }

        let signature = data[offset..offset+sig_len].to_vec();

        Ok(Self {
            group_id,
            sender_identity,
            chain_id,
            iteration,
            ciphertext,
            auth_tag,
            signature,
        })
    }
}

pub struct SenderKeyContext {
    pub my_identity: IdentityKeyPair,
    pub group_id: [u8; 32],
    pub chain: SenderKeyChain,
    pub chain_id: u32,
}

impl SenderKeyContext {
    #[must_use]
    pub const fn new(my_identity: IdentityKeyPair, group_id: &[u8; 32], seed: &[u8; 32], chain_id: u32) -> Self {
        Self {
            my_identity,
            group_id: *group_id,
            chain: SenderKeyChain::new(seed, 0),
            chain_id,
        }
    }

    pub async fn get_distribution_message(&self) -> SenderKeyDistributionMessage {
        SenderKeyDistributionMessage {
            group_id: self.group_id,
            sender_identity: self.my_identity.public_key().await,
            chain_id: self.chain_id,
            iteration: self.chain.iteration,
            chain_key: self.chain.chain_key,
        }
    }

    pub async fn encrypt(&mut self, plaintext: &[u8]) -> Result<SenderKeyMessage, E2EError> {
        let iteration = self.chain.iteration;
        let (key, iv) = self.chain.next_message_key();
        
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.chain_id.to_le_bytes());
        aad.extend_from_slice(&iteration.to_le_bytes());

        let mut ciphertext = vec![0u8; plaintext.len()];
        let auth_tag = aes256_gcm_encrypt(&key, &iv, &aad, plaintext, &mut ciphertext);

        // Sign the ciphertext + aad + sender_identity
        let mut msg_to_sign = Vec::new();
        let pub_key = self.my_identity.public_key().await;
        let id_bytes = pub_key.serialize();
        msg_to_sign.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        msg_to_sign.extend_from_slice(&id_bytes);
        msg_to_sign.extend_from_slice(&aad);
        msg_to_sign.extend_from_slice(&ciphertext);
        msg_to_sign.extend_from_slice(&auth_tag);

        let rnd = [0u8; 32]; // Replace with proper entropy in real app if possible, or 0s as deterministic
        let signature = self.my_identity.sign(&msg_to_sign, &rnd).await
            .map_err(|_| E2EError::SigningError)?;

        Ok(SenderKeyMessage {
            group_id: self.group_id,
            sender_identity: pub_key,
            chain_id: self.chain_id,
            iteration,
            ciphertext,
            auth_tag,
            signature,
        })
    }
}

pub struct SenderKeyReceiver {
    pub group_id: [u8; 32],
    pub sender_identity: IdentityPublicKey,
    pub chain_id: u32,
    pub chain: SenderKeyChain,
}

impl SenderKeyReceiver {
    #[must_use]
    pub fn from_distribution_message(msg: &SenderKeyDistributionMessage) -> Self {
        Self {
            group_id: msg.group_id,
            sender_identity: msg.sender_identity.clone(),
            chain_id: msg.chain_id,
            chain: SenderKeyChain::new(&msg.chain_key, msg.iteration),
        }
    }

    pub fn decrypt(&mut self, msg: &SenderKeyMessage) -> Result<Vec<u8>, E2EError> {
        if self.group_id != msg.group_id || self.chain_id != msg.chain_id || self.sender_identity != msg.sender_identity {
            return Err(E2EError::InvalidMessageFormat);
        }

        // Verify signature against trusted sender identity
        let mut msg_to_sign = Vec::new();
        let id_bytes = self.sender_identity.serialize();
        msg_to_sign.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
        msg_to_sign.extend_from_slice(&id_bytes);
        
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.group_id);
        aad.extend_from_slice(&self.chain_id.to_le_bytes());
        aad.extend_from_slice(&msg.iteration.to_le_bytes());

        msg_to_sign.extend_from_slice(&aad);
        msg_to_sign.extend_from_slice(&msg.ciphertext);
        msg_to_sign.extend_from_slice(&msg.auth_tag);

        if !self.sender_identity.verify(&msg_to_sign, &msg.signature) {
            return Err(E2EError::InvalidSignature);
        }

        // Advance chain if needed
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        
        if msg.iteration < self.chain.iteration {
            return Err(E2EError::MessageOutOfOrder);
        }

        // Prevent CPU exhaustion DoS attacks by capping the number of allowed skipped iterations.
        if msg.iteration.saturating_sub(self.chain.iteration) > 2000 {
            return Err(E2EError::MessageOutOfOrder);
        }

        // Atomic advancement: use a temporary chain copy so failed decryptions do not corrupt state
        let mut temp_chain = self.chain.clone();
        while temp_chain.iteration <= msg.iteration {
            let res = temp_chain.next_message_key();
            key = res.0;
            iv = res.1;
        }

        let mut plaintext = vec![0u8; msg.ciphertext.len()];
        if aes256_gcm_decrypt(&key, &iv, &aad, &msg.ciphertext, &msg.auth_tag, &mut plaintext).is_err() {
            return Err(E2EError::DecryptionError);
        }
        
        self.chain = temp_chain;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sender_keys_roundtrip() {
        use crate::ffi::block_on;
        let alice_identity = IdentityKeyPair::generate(&[1; 32], &[2; 32]);
        
        let group_id = [9; 32];
        let seed = [10; 32];
        let mut context = SenderKeyContext::new(alice_identity, &group_id, &seed, 1);
        
        let dist_msg = block_on(context.get_distribution_message());
        let mut receiver = SenderKeyReceiver::from_distribution_message(&dist_msg);
        
        let plaintext = b"Hello group members!";
        let msg = block_on(context.encrypt(plaintext)).unwrap();
        
        let decrypted = receiver.decrypt(&msg).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }
}
