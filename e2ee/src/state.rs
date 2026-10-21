use alloc::vec::Vec;
use crate::errors::E2EError;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::utils::zeroize;

pub const STATE_VERSION_V1: u32 = 1;

#[derive(Clone)]
pub struct SkippedKeyState {
    pub peer_dh_public: [u8; 32],
    pub message_number: u32,
    pub key: [u8; 32],
    pub iv: [u8; 12],
}

impl Drop for SkippedKeyState {
    fn drop(&mut self) {
        zeroize(&mut self.key);
        zeroize(&mut self.iv);
    }
}

#[derive(Clone)]
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub dh_send_private: [u8; 32],
    pub dh_send_public: [u8; 32],
    pub dh_recv_public: Option<[u8; 32]>,
    pub kem_send_private: [u8; 2400],
    pub kem_send_public: [u8; 1184],
    pub kem_recv_public: Option<[u8; 1184]>,
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    pub send_msg_num: u32,
    pub recv_msg_num: u32,
    pub prev_send_msg_num: u32,
    pub skipped_message_keys: Vec<SkippedKeyState>,
    pub past_epochs: Vec<PastEpochState>,
}

#[derive(Clone)]
pub struct PastEpochState {
    pub dh_recv_public: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub recv_msg_num: u32,
}

impl Drop for PastEpochState {
    fn drop(&mut self) {
        zeroize(&mut self.recv_chain_key);
    }
}

impl Drop for DoubleRatchetState {
    fn drop(&mut self) {
        zeroize(&mut self.root_key);
        zeroize(&mut self.dh_send_private);
        zeroize(&mut self.kem_send_private);
        if let Some(mut sc) = self.send_chain_key { zeroize(&mut sc); }
        if let Some(mut rc) = self.recv_chain_key { zeroize(&mut rc); }
        self.skipped_message_keys.clear();
    }
}

#[derive(Clone)]
pub struct SessionState {
    pub version: u32,
    pub ratchet: DoubleRatchetState,
    pub pending_kem_ciphertext: Option<[u8; 1088]>,
}

impl SessionState {
    #[must_use]
    pub const fn new(ratchet: DoubleRatchetState, pending_kem_ciphertext: Option<[u8; 1088]>) -> Self {
        Self {
            version: STATE_VERSION_V1,
            ratchet,
            pending_kem_ciphertext,
        }
    }
}

        // Remove standard Serialize implementation and add secure ones
impl SessionState {
    pub fn serialize_secure(&self, master_key: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::new();
        // Ratchet fields
        payload.extend_from_slice(&self.ratchet.root_key);
        payload.extend_from_slice(&self.ratchet.dh_send_private);
        payload.extend_from_slice(&self.ratchet.dh_send_public);
        
        if let Some(dh_recv) = &self.ratchet.dh_recv_public {
            payload.push(1);
            payload.extend_from_slice(dh_recv);
        } else {
            payload.push(0);
        }

        payload.extend_from_slice(&self.ratchet.kem_send_private);
        payload.extend_from_slice(&self.ratchet.kem_send_public);

        if let Some(kem_recv) = &self.ratchet.kem_recv_public {
            payload.push(1);
            payload.extend_from_slice(kem_recv);
        } else {
            payload.push(0);
        }

        if let Some(send_chain) = &self.ratchet.send_chain_key {
            payload.push(1);
            payload.extend_from_slice(send_chain);
        } else {
            payload.push(0);
        }

        if let Some(recv_chain) = &self.ratchet.recv_chain_key {
            payload.push(1);
            payload.extend_from_slice(recv_chain);
        } else {
            payload.push(0);
        }

        payload.extend_from_slice(&self.ratchet.send_msg_num.to_le_bytes());
        payload.extend_from_slice(&self.ratchet.recv_msg_num.to_le_bytes());
        payload.extend_from_slice(&self.ratchet.prev_send_msg_num.to_le_bytes());

        payload.extend_from_slice(&(self.ratchet.skipped_message_keys.len() as u32).to_le_bytes());
        for sk in &self.ratchet.skipped_message_keys {
            payload.extend_from_slice(&sk.peer_dh_public);
            payload.extend_from_slice(&sk.message_number.to_le_bytes());
            payload.extend_from_slice(&sk.key);
            payload.extend_from_slice(&sk.iv);
        }

        payload.extend_from_slice(&(self.ratchet.past_epochs.len() as u32).to_le_bytes());
        for epoch in &self.ratchet.past_epochs {
            payload.extend_from_slice(&epoch.dh_recv_public);
            payload.extend_from_slice(&epoch.recv_chain_key);
            payload.extend_from_slice(&epoch.recv_msg_num.to_le_bytes());
        }

        if let Some(kem_ct) = &self.pending_kem_ciphertext {
            payload.push(1);
            payload.extend_from_slice(kem_ct);
        } else {
            payload.push(0);
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);
        
        let mut iv = [0u8; 12];
        let mut iv_info = Vec::with_capacity(8 + 4 + 4 + 4 + 32);
        iv_info.extend_from_slice(b"STATE_IV");
        iv_info.extend_from_slice(&self.ratchet.send_msg_num.to_le_bytes());
        iv_info.extend_from_slice(&self.ratchet.recv_msg_num.to_le_bytes());
        iv_info.extend_from_slice(&self.ratchet.prev_send_msg_num.to_le_bytes());
        let mut h = hybrid_crypto::sha2::Sha256::new();
        h.update(&buf);
        let digest = h.finalize();
        iv_info.extend_from_slice(&digest);
        hybrid_crypto::hkdf::hkdf_expand(master_key, &iv_info, &mut iv);
        
        let mut ct = alloc::vec![0u8; buf.len()];
        let tag = aes256_gcm_encrypt(master_key, &iv, &[], &buf, &mut ct);
        
        let mut out = Vec::with_capacity(12 + ct.len() + 16);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        
        out
    }

    pub fn serialize_secure_with_iv(&self, master_key: &[u8; 32], iv: &[u8; 12]) -> Vec<u8> {
        let mut payload = Vec::new();
        // Ratchet fields
        payload.extend_from_slice(&self.ratchet.root_key);
        payload.extend_from_slice(&self.ratchet.dh_send_private);
        payload.extend_from_slice(&self.ratchet.dh_send_public);
        
        if let Some(dh_recv) = &self.ratchet.dh_recv_public {
            payload.push(1);
            payload.extend_from_slice(dh_recv);
        } else {
            payload.push(0);
        }

        payload.extend_from_slice(&self.ratchet.kem_send_private);
        payload.extend_from_slice(&self.ratchet.kem_send_public);

        if let Some(kem_recv) = &self.ratchet.kem_recv_public {
            payload.push(1);
            payload.extend_from_slice(kem_recv);
        } else {
            payload.push(0);
        }

        if let Some(send_chain) = &self.ratchet.send_chain_key {
            payload.push(1);
            payload.extend_from_slice(send_chain);
        } else {
            payload.push(0);
        }

        if let Some(recv_chain) = &self.ratchet.recv_chain_key {
            payload.push(1);
            payload.extend_from_slice(recv_chain);
        } else {
            payload.push(0);
        }

        payload.extend_from_slice(&self.ratchet.send_msg_num.to_le_bytes());
        payload.extend_from_slice(&self.ratchet.recv_msg_num.to_le_bytes());
        payload.extend_from_slice(&self.ratchet.prev_send_msg_num.to_le_bytes());

        payload.extend_from_slice(&(self.ratchet.skipped_message_keys.len() as u32).to_le_bytes());
        for sk in &self.ratchet.skipped_message_keys {
            payload.extend_from_slice(&sk.peer_dh_public);
            payload.extend_from_slice(&sk.message_number.to_le_bytes());
            payload.extend_from_slice(&sk.key);
            payload.extend_from_slice(&sk.iv);
        }

        payload.extend_from_slice(&(self.ratchet.past_epochs.len() as u32).to_le_bytes());
        for epoch in &self.ratchet.past_epochs {
            payload.extend_from_slice(&epoch.dh_recv_public);
            payload.extend_from_slice(&epoch.recv_chain_key);
            payload.extend_from_slice(&epoch.recv_msg_num.to_le_bytes());
        }

        if let Some(kem_ct) = &self.pending_kem_ciphertext {
            payload.push(1);
            payload.extend_from_slice(kem_ct);
        } else {
            payload.push(0);
        }

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&payload);
        
        let mut ct = alloc::vec![0u8; buf.len()];
        let tag = aes256_gcm_encrypt(master_key, iv, &[], &buf, &mut ct);
        
        let mut out = Vec::with_capacity(12 + ct.len() + 16);
        out.extend_from_slice(iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        
        out
    }

    pub fn deserialize_secure(data: &[u8], master_key: &[u8; 32]) -> Result<Self, E2EError> {
        if data.len() < 12 + 16 {
            return Err(E2EError::InvalidMessageFormat); // truncated
        }

        let mut iv = [0u8; 12];
        iv.copy_from_slice(&data[0..12]);
        let tag_offset = data.len() - 16;
        let ct = &data[12..tag_offset];
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[tag_offset..]);
        
        let mut decrypted = alloc::vec![0u8; ct.len()];
        let tag_arr = <[u8; 16]>::try_from(tag).map_err(|_| E2EError::InvalidMessageFormat)?;
        aes256_gcm_decrypt(master_key, &iv, &[], ct, &tag_arr, &mut decrypted).map_err(|_| E2EError::InvalidMessageFormat)?;
        let data = decrypted.as_slice();

        let mut offset = 0;
        
        let mut v_bytes = [0u8; 4];
        v_bytes.copy_from_slice(&data[offset..offset+4]);
        let version = u32::from_le_bytes(v_bytes);
        if version != STATE_VERSION_V1 {
            return Err(E2EError::InvalidMessageFormat); // Unsupported version
        }
        offset += 4;

        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[offset..offset+4]);
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        offset += 4;

        if data.len() != offset + payload_len {
            return Err(E2EError::InvalidMessageFormat); // Length mismatch
        }

        let mut ratchet = DoubleRatchetState {
            root_key: [0u8; 32],
            dh_send_private: [0u8; 32],
            dh_send_public: [0u8; 32],
            dh_recv_public: None,
            kem_send_private: [0u8; 2400],
            kem_send_public: [0u8; 1184],
            kem_recv_public: None,
            send_chain_key: None,
            recv_chain_key: None,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_msg_num: 0,
            skipped_message_keys: Vec::new(),
            past_epochs: Vec::new(),
        };

        if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        ratchet.root_key.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        ratchet.dh_send_private.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        ratchet.dh_send_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 1 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let mut dh = [0u8; 32];
            dh.copy_from_slice(&data[offset..offset+32]);
            ratchet.dh_recv_public = Some(dh);
            offset += 32;
        } else {
            offset += 1;
        }

        if offset + 2400 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        ratchet.kem_send_private.copy_from_slice(&data[offset..offset+2400]);
        offset += 2400;

        if offset + 1184 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        ratchet.kem_send_public.copy_from_slice(&data[offset..offset+1184]);
        offset += 1184;

        if offset + 1 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 1184 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let mut kp = [0u8; 1184];
            kp.copy_from_slice(&data[offset..offset+1184]);
            ratchet.kem_recv_public = Some(kp);
            offset += 1184;
        } else {
            offset += 1;
        }

        if offset + 1 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&data[offset..offset+32]);
            ratchet.send_chain_key = Some(sk);
            offset += 32;
        } else {
            offset += 1;
        }

        if offset + 1 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let mut rk = [0u8; 32];
            rk.copy_from_slice(&data[offset..offset+32]);
            ratchet.recv_chain_key = Some(rk);
            offset += 32;
        } else {
            offset += 1;
        }

        if offset + 12 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        
        let mut b = [0u8; 4];
        b.copy_from_slice(&data[offset..offset+4]);
        ratchet.send_msg_num = u32::from_le_bytes(b);
        offset += 4;
        
        b.copy_from_slice(&data[offset..offset+4]);
        ratchet.recv_msg_num = u32::from_le_bytes(b);
        offset += 4;
        
        b.copy_from_slice(&data[offset..offset+4]);
        ratchet.prev_send_msg_num = u32::from_le_bytes(b);
        offset += 4;

        if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        b.copy_from_slice(&data[offset..offset+4]);
        let skipped_keys_len = u32::from_le_bytes(b) as usize;
        offset += 4;
        
        // Anti-DoS bounds checking
        if skipped_keys_len > 2000 { return Err(E2EError::InvalidMessageFormat); }
        if offset + skipped_keys_len * (32 + 4 + 32 + 12) > data.len() { return Err(E2EError::InvalidMessageFormat); }

        for _ in 0..skipped_keys_len {
            let mut peer_dh_public = [0u8; 32];
            peer_dh_public.copy_from_slice(&data[offset..offset+32]);
            offset += 32;
            
            b.copy_from_slice(&data[offset..offset+4]);
            let message_number = u32::from_le_bytes(b);
            offset += 4;
            
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[offset..offset+32]);
            offset += 32;
            
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&data[offset..offset+12]);
            offset += 12;
            
            ratchet.skipped_message_keys.push(SkippedKeyState { peer_dh_public, message_number, key, iv });
        }

        if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        b.copy_from_slice(&data[offset..offset+4]);
        let past_dh_len = u32::from_le_bytes(b) as usize;
        offset += 4;

        if past_dh_len > 100 { return Err(E2EError::InvalidMessageFormat); }
        if offset + past_dh_len * (32 + 32 + 4) > data.len() { return Err(E2EError::InvalidMessageFormat); }

        for _ in 0..past_dh_len {
            let mut p = [0u8; 32];
            p.copy_from_slice(&data[offset..offset+32]);
            offset += 32;

            let mut ck = [0u8; 32];
            ck.copy_from_slice(&data[offset..offset+32]);
            offset += 32;

            b.copy_from_slice(&data[offset..offset+4]);
            let msg_num = u32::from_le_bytes(b);
            offset += 4;

            ratchet.past_epochs.push(PastEpochState {
                dh_recv_public: p,
                recv_chain_key: ck,
                recv_msg_num: msg_num,
            });
        }

        let mut pending_kem_ciphertext = None;
        if offset + 1 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 1088 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let mut ct = [0u8; 1088];
            ct.copy_from_slice(&data[offset..offset+1088]);
            pending_kem_ciphertext = Some(ct);
        }

        Ok(Self {
            version,
            ratchet,
            pending_kem_ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn create_dummy_state() -> SessionState {
        let ratchet = DoubleRatchetState {
            root_key: [1; 32],
            dh_send_private: [2; 32],
            dh_send_public: [3; 32],
            dh_recv_public: Some([4; 32]),
            kem_send_private: [5; 2400],
            kem_send_public: [6; 1184],
            kem_recv_public: Some([7; 1184]),
            send_chain_key: Some([8; 32]),
            recv_chain_key: Some([9; 32]),
            send_msg_num: 10,
            recv_msg_num: 11,
            prev_send_msg_num: 12,
            skipped_message_keys: vec![
                SkippedKeyState {
                    peer_dh_public: [13; 32],
                    message_number: 14,
                    key: [15; 32],
                    iv: [16; 12],
                }
            ],
            past_epochs: vec![PastEpochState {
                dh_recv_public: [17; 32],
                recv_chain_key: [18; 32],
                recv_msg_num: 19,
            }],
        };

        SessionState::new(ratchet, Some([20; 1088]))
    }

    #[test]
    fn test_session_state_roundtrip() {
        let state = create_dummy_state();
        let master_key = [0x42; 32];
        let bytes = state.serialize_secure(&master_key);
        let restored = SessionState::deserialize_secure(&bytes, &master_key).unwrap();

        assert_eq!(state.version, restored.version);
        assert_eq!(state.ratchet.root_key, restored.ratchet.root_key);
        assert_eq!(state.ratchet.kem_send_private, restored.ratchet.kem_send_private);
        assert_eq!(state.ratchet.skipped_message_keys.len(), restored.ratchet.skipped_message_keys.len());
        assert_eq!(state.ratchet.skipped_message_keys[0].message_number, restored.ratchet.skipped_message_keys[0].message_number);
        assert_eq!(state.pending_kem_ciphertext.unwrap(), restored.pending_kem_ciphertext.unwrap());
    }

    #[test]
    fn test_session_state_corruption() {
        let state = create_dummy_state();
        let master_key = [0x42; 32];
        let mut bytes = state.serialize_secure(&master_key);

        // Flip a byte in the payload
        bytes[50] ^= 0x01;
        assert!(SessionState::deserialize_secure(&bytes, &master_key).is_err());

        // Restore and flip a byte in checksum
        bytes[50] ^= 0x01;
        let len = bytes.len();
        bytes[len - 5] ^= 0x01;
        assert!(SessionState::deserialize_secure(&bytes, &master_key).is_err());
    }

    #[test]
    fn test_session_state_truncation() {
        let state = create_dummy_state();
        let master_key = [0x42; 32];
        let mut bytes = state.serialize_secure(&master_key);

        bytes.pop(); // truncate 1 byte
        assert!(SessionState::deserialize_secure(&bytes, &master_key).is_err());
    }
}
