use alloc::vec::Vec;
use crate::errors::E2EError;
use hybrid_crypto::sha2::Sha256;
use hybrid_crypto::utils::{constant_time_eq, zeroize};
use crate::serialization::Serialize;

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
    pub past_dh_recv_publics: Vec<[u8; 32]>,
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
    pub fn new(ratchet: DoubleRatchetState, pending_kem_ciphertext: Option<[u8; 1088]>) -> Self {
        Self {
            version: STATE_VERSION_V1,
            ratchet,
            pending_kem_ciphertext,
        }
    }
}

impl Serialize for SessionState {
    fn serialize(&self) -> Vec<u8> {
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

        payload.extend_from_slice(&(self.ratchet.past_dh_recv_publics.len() as u32).to_le_bytes());
        for pk in &self.ratchet.past_dh_recv_publics {
            payload.extend_from_slice(pk);
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
        
        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let checksum = hasher.finalize();
        buf.extend_from_slice(&checksum);
        
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        if data.len() < 4 + 4 + 32 {
            return Err(E2EError::InvalidMessageFormat); // truncated
        }

        let expected_checksum = &data[data.len() - 32..];
        let content = &data[..data.len() - 32];

        let mut hasher = Sha256::new();
        hasher.update(content);
        let actual_checksum = hasher.finalize();

        if !constant_time_eq(expected_checksum, &actual_checksum) {
            return Err(E2EError::InvalidMessageFormat); // Corruption detected
        }

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

        if data.len() != offset + payload_len + 32 {
            return Err(E2EError::InvalidMessageFormat); // Length mismatch
        }

        let mut root_key = [0u8; 32];
        if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        root_key.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut dh_send_private = [0u8; 32];
        if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        dh_send_private.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut dh_send_public = [0u8; 32];
        if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        dh_send_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        let mut dh_recv_public = None;
        if offset + 1 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
            let mut dh = [0u8; 32];
            dh.copy_from_slice(&data[offset..offset+32]);
            dh_recv_public = Some(dh);
            offset += 32;
        } else {
            offset += 1;
        }

        let mut kem_send_private = [0u8; 2400];
        if offset + 2400 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        kem_send_private.copy_from_slice(&data[offset..offset+2400]);
        offset += 2400;

        let mut kem_send_public = [0u8; 1184];
        if offset + 1184 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        kem_send_public.copy_from_slice(&data[offset..offset+1184]);
        offset += 1184;

        let mut kem_recv_public = None;
        if offset + 1 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 1184 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
            let mut kp = [0u8; 1184];
            kp.copy_from_slice(&data[offset..offset+1184]);
            kem_recv_public = Some(kp);
            offset += 1184;
        } else {
            offset += 1;
        }

        let mut send_chain_key = None;
        if offset + 1 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&data[offset..offset+32]);
            send_chain_key = Some(sk);
            offset += 32;
        } else {
            offset += 1;
        }

        let mut recv_chain_key = None;
        if offset + 1 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
            let mut rk = [0u8; 32];
            rk.copy_from_slice(&data[offset..offset+32]);
            recv_chain_key = Some(rk);
            offset += 32;
        } else {
            offset += 1;
        }

        if offset + 12 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        
        let mut b = [0u8; 4];
        b.copy_from_slice(&data[offset..offset+4]);
        let send_msg_num = u32::from_le_bytes(b);
        offset += 4;
        
        b.copy_from_slice(&data[offset..offset+4]);
        let recv_msg_num = u32::from_le_bytes(b);
        offset += 4;
        
        b.copy_from_slice(&data[offset..offset+4]);
        let prev_send_msg_num = u32::from_le_bytes(b);
        offset += 4;

        if offset + 4 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        b.copy_from_slice(&data[offset..offset+4]);
        let skipped_keys_len = u32::from_le_bytes(b) as usize;
        offset += 4;
        
        // Anti-DoS bounds checking
        if skipped_keys_len > 2000 { return Err(E2EError::InvalidMessageFormat); }
        if offset + skipped_keys_len * (32 + 4 + 32 + 12) > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }

        let mut skipped_message_keys = Vec::with_capacity(skipped_keys_len);
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
            
            skipped_message_keys.push(SkippedKeyState { peer_dh_public, message_number, key, iv });
        }

        if offset + 4 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        b.copy_from_slice(&data[offset..offset+4]);
        let past_dh_len = u32::from_le_bytes(b) as usize;
        offset += 4;

        if past_dh_len > 100 { return Err(E2EError::InvalidMessageFormat); }
        if offset + past_dh_len * 32 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }

        let mut past_dh_recv_publics = Vec::with_capacity(past_dh_len);
        for _ in 0..past_dh_len {
            let mut p = [0u8; 32];
            p.copy_from_slice(&data[offset..offset+32]);
            past_dh_recv_publics.push(p);
            offset += 32;
        }

        let mut pending_kem_ciphertext = None;
        if offset + 1 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
        if data[offset] == 1 {
            offset += 1;
            if offset + 1088 > data.len() - 32 { return Err(E2EError::InvalidMessageFormat); }
            let mut ct = [0u8; 1088];
            ct.copy_from_slice(&data[offset..offset+1088]);
            pending_kem_ciphertext = Some(ct);
            // offset += 1088; // Not strictly necessary since we're done
        }

        let ratchet = DoubleRatchetState {
            root_key,
            dh_send_private,
            dh_send_public,
            dh_recv_public,
            kem_send_private,
            kem_send_public,
            kem_recv_public,
            send_chain_key,
            recv_chain_key,
            send_msg_num,
            recv_msg_num,
            prev_send_msg_num,
            skipped_message_keys,
            past_dh_recv_publics,
        };

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
            past_dh_recv_publics: vec![[17; 32]],
        };

        SessionState::new(ratchet, Some([18; 1088]))
    }

    #[test]
    fn test_session_state_roundtrip() {
        let state = create_dummy_state();
        let bytes = state.serialize();
        let restored = SessionState::deserialize(&bytes).unwrap();

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
        let mut bytes = state.serialize();

        // Flip a byte in the payload
        bytes[50] ^= 0x01;
        assert!(SessionState::deserialize(&bytes).is_err());

        // Restore and flip a byte in checksum
        bytes[50] ^= 0x01;
        let len = bytes.len();
        bytes[len - 5] ^= 0x01;
        assert!(SessionState::deserialize(&bytes).is_err());
    }

    #[test]
    fn test_session_state_truncation() {
        let state = create_dummy_state();
        let mut bytes = state.serialize();

        bytes.pop(); // truncate 1 byte
        assert!(SessionState::deserialize(&bytes).is_err());
    }
}
