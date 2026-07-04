use alloc::vec::Vec;
use crate::errors::E2EError;
use crate::identity::IdentityPublicKey;
use crate::prekeys::PreKeyBundle;
use crate::messages::{Message, MessageHeader, PreKeyMessage};

pub const PROTOCOL_VERSION_V1: u16 = 1;

pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(data: &[u8]) -> Result<Self, E2EError> where Self: Sized;
}

impl Serialize for IdentityPublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 4 + self.pqc_public.len());
        buf.extend_from_slice(&self.ecc_public);
        buf.extend_from_slice(&(self.pqc_public.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.pqc_public);
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        if data.len() < 36 {
            return Err(E2EError::InvalidMessageFormat);
        }
        let mut ecc_public = [0u8; 32];
        ecc_public.copy_from_slice(&data[0..32]);
        
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[32..36]);
        let pqc_len = u32::from_le_bytes(len_bytes) as usize;
        
        if data.len().saturating_sub(36) < pqc_len {
            return Err(E2EError::InvalidMessageFormat);
        }
        
        let pqc_public = data[36..36+pqc_len].to_vec();
        
        Ok(Self {
            ecc_public,
            pqc_public,
        })
    }
}

impl Serialize for PreKeyBundle {
    fn serialize(&self) -> Vec<u8> {
        let id_pub = self.identity_key.serialize();
        let mut buf = Vec::new();
        buf.extend_from_slice(&(id_pub.len() as u32).to_le_bytes());
        buf.extend_from_slice(&id_pub);
        
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        buf.extend_from_slice(&self.signed_prekey_ecc_public);
        buf.extend_from_slice(&self.signed_prekey_pqc_public);
        
        buf.extend_from_slice(&(self.signed_prekey_signature.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.signed_prekey_signature);
        
        if let (Some(opk_id), Some(ecc), Some(pqc)) = (
            self.one_time_prekey_id,
            &self.one_time_prekey_ecc_public,
            &self.one_time_prekey_pqc_public,
        ) {
            buf.push(1); // Has OPK
            buf.extend_from_slice(&opk_id.to_le_bytes());
            buf.extend_from_slice(ecc);
            buf.extend_from_slice(pqc);
        } else {
            buf.push(0); // No OPK
        }
        
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut offset = 0;
        
        if data.len() < offset + 4 { return Err(E2EError::InvalidMessageFormat); }
        let mut id_pub_len_bytes = [0u8; 4];
        id_pub_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let id_pub_len = u32::from_le_bytes(id_pub_len_bytes) as usize;
        offset += 4;
        
        if data.len().saturating_sub(offset) < id_pub_len { return Err(E2EError::InvalidMessageFormat); }
        let identity_key = IdentityPublicKey::deserialize(&data[offset..offset+id_pub_len])?;
        offset += id_pub_len;
        
        if data.len().saturating_sub(offset) < 4 + 32 + 1184 + 4 { return Err(E2EError::InvalidMessageFormat); }
        
        let mut spk_id_bytes = [0u8; 4];
        spk_id_bytes.copy_from_slice(&data[offset..offset+4]);
        let signed_prekey_id = u32::from_le_bytes(spk_id_bytes);
        offset += 4;
        
        let mut signed_prekey_ecc_public = [0u8; 32];
        signed_prekey_ecc_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;
        
        let mut signed_prekey_pqc_public = [0u8; 1184];
        signed_prekey_pqc_public.copy_from_slice(&data[offset..offset+1184]);
        offset += 1184;
        
        let mut sig_len_bytes = [0u8; 4];
        sig_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let sig_len = u32::from_le_bytes(sig_len_bytes) as usize;
        offset += 4;
        
        if data.len().saturating_sub(offset).saturating_sub(1) < sig_len { return Err(E2EError::InvalidMessageFormat); }
        let signed_prekey_signature = data[offset..offset+sig_len].to_vec();
        offset += sig_len;
        
        let has_opk = data[offset] == 1;
        offset += 1;
        
        let mut one_time_prekey_id = None;
        let mut one_time_prekey_ecc_public = None;
        let mut one_time_prekey_pqc_public = None;
        
        if has_opk {
            if data.len().saturating_sub(offset) < 4 + 32 + 1184 { return Err(E2EError::InvalidMessageFormat); }
            let mut opk_id_bytes = [0u8; 4];
            opk_id_bytes.copy_from_slice(&data[offset..offset+4]);
            one_time_prekey_id = Some(u32::from_le_bytes(opk_id_bytes));
            offset += 4;
            
            let mut ecc = [0u8; 32];
            ecc.copy_from_slice(&data[offset..offset+32]);
            one_time_prekey_ecc_public = Some(ecc);
            offset += 32;
            
            let mut pqc = [0u8; 1184];
            pqc.copy_from_slice(&data[offset..offset+1184]);
            one_time_prekey_pqc_public = Some(pqc);
        }
        
        Ok(Self {
            identity_key,
            signed_prekey_id,
            signed_prekey_ecc_public,
            signed_prekey_pqc_public,
            signed_prekey_signature,
            one_time_prekey_id,
            one_time_prekey_ecc_public,
            one_time_prekey_pqc_public,
        })
    }
}

impl Serialize for Message {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&self.header.dh_public);
        buf.extend_from_slice(&self.header.kem_public);
        buf.extend_from_slice(&self.header.kem_ciphertext);
        buf.extend_from_slice(&self.header.previous_chain_length.to_le_bytes());
        buf.extend_from_slice(&self.header.message_number.to_le_bytes());
        // Ciphertext
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ciphertext);
        // Auth tag
        buf.extend_from_slice(&self.auth_tag);
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let min_len = 32 + 1184 + 1088 + 4 + 4 + 4 + 16;
        if data.len() < min_len {
            return Err(E2EError::InvalidMessageFormat);
        }
        
        let mut offset = 0;
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;
        
        let mut kem_public = [0u8; 1184];
        kem_public.copy_from_slice(&data[offset..offset+1184]);
        offset += 1184;
        
        let mut kem_ciphertext = [0u8; 1088];
        kem_ciphertext.copy_from_slice(&data[offset..offset+1088]);
        offset += 1088;
        
        let mut prev_len_bytes = [0u8; 4];
        prev_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let previous_chain_length = u32::from_le_bytes(prev_len_bytes);
        offset += 4;
        
        let mut msg_num_bytes = [0u8; 4];
        msg_num_bytes.copy_from_slice(&data[offset..offset+4]);
        let message_number = u32::from_le_bytes(msg_num_bytes);
        offset += 4;
        
        let mut ct_len_bytes = [0u8; 4];
        ct_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;
        offset += 4;
        
        if data.len().saturating_sub(offset).saturating_sub(16) < ct_len {
            return Err(E2EError::InvalidMessageFormat);
        }
        
        let ciphertext = data[offset..offset+ct_len].to_vec();
        offset += ct_len;
        
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&data[offset..offset+16]);
        
        Ok(Self {
            header: MessageHeader {
                dh_public,
                kem_public,
                kem_ciphertext,
                previous_chain_length,
                message_number,
            },
            ciphertext,
            auth_tag,
        })
    }
}

impl Serialize for PreKeyMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // OPK ID
        if let Some(opk_id) = self.prekey_id {
            buf.push(1);
            buf.extend_from_slice(&opk_id.to_le_bytes());
        } else {
            buf.push(0);
        }
        // SPK ID
        buf.extend_from_slice(&self.signed_prekey_id.to_le_bytes());
        // Identity Key (Hybrid: ECC + PQC)
        buf.extend_from_slice(&self.initiator_identity_ecc_public);
        buf.extend_from_slice(&(self.initiator_identity_pqc_public.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.initiator_identity_pqc_public);
        // Ephemeral ECC
        buf.extend_from_slice(&self.initiator_ephemeral_ecc_public);
        // SPK Ciphertext
        buf.extend_from_slice(&self.pqc_ciphertext_spk);
        // OPK Ciphertext
        if let Some(ct_opk) = &self.pqc_ciphertext_opk {
            buf.push(1);
            buf.extend_from_slice(ct_opk);
        } else {
            buf.push(0);
        }
        // Initial Message
        let msg_bytes = self.initial_message.serialize();
        buf.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&msg_bytes);
        
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        if data.is_empty() {
            return Err(E2EError::InvalidMessageFormat);
        }
        let mut offset = 0;
        
        let has_opk = data[offset] == 1;
        offset += 1;
        
        let mut prekey_id = None;
        if has_opk {
            if data.len().saturating_sub(offset) < 4 { return Err(E2EError::InvalidMessageFormat); }
            let mut opk_id_bytes = [0u8; 4];
            opk_id_bytes.copy_from_slice(&data[offset..offset+4]);
            prekey_id = Some(u32::from_le_bytes(opk_id_bytes));
            offset += 4;
        }
        
        if data.len().saturating_sub(offset) < 4 + 32 + 4 { return Err(E2EError::InvalidMessageFormat); }
        let mut spk_id_bytes = [0u8; 4];
        spk_id_bytes.copy_from_slice(&data[offset..offset+4]);
        let signed_prekey_id = u32::from_le_bytes(spk_id_bytes);
        offset += 4;
        
        let mut initiator_identity_ecc_public = [0u8; 32];
        initiator_identity_ecc_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;
        
        let mut pqc_id_len_bytes = [0u8; 4];
        pqc_id_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let pqc_id_len = u32::from_le_bytes(pqc_id_len_bytes) as usize;
        offset += 4;
        
        if data.len().saturating_sub(offset).saturating_sub(32 + 1088 + 1) < pqc_id_len { return Err(E2EError::InvalidMessageFormat); }
        let initiator_identity_pqc_public = data[offset..offset+pqc_id_len].to_vec();
        offset += pqc_id_len;
        
        let mut initiator_ephemeral_ecc_public = [0u8; 32];
        initiator_ephemeral_ecc_public.copy_from_slice(&data[offset..offset+32]);
        offset += 32;
        
        let mut pqc_ciphertext_spk = [0u8; 1088];
        pqc_ciphertext_spk.copy_from_slice(&data[offset..offset+1088]);
        offset += 1088;
        
        let has_ct_opk = data[offset] == 1;
        offset += 1;
        
        let mut pqc_ciphertext_opk = None;
        if has_ct_opk {
            if data.len().saturating_sub(offset) < 1088 { return Err(E2EError::InvalidMessageFormat); }
            let mut ct = [0u8; 1088];
            ct.copy_from_slice(&data[offset..offset+1088]);
            pqc_ciphertext_opk = Some(ct);
            offset += 1088;
        }
        
        if data.len().saturating_sub(offset) < 4 { return Err(E2EError::InvalidMessageFormat); }
        let mut msg_len_bytes = [0u8; 4];
        msg_len_bytes.copy_from_slice(&data[offset..offset+4]);
        let msg_len = u32::from_le_bytes(msg_len_bytes) as usize;
        offset += 4;
        
        if data.len().saturating_sub(offset) < msg_len { return Err(E2EError::InvalidMessageFormat); }
        let initial_message = Message::deserialize(&data[offset..offset+msg_len])?;
        
        Ok(Self {
            prekey_id,
            signed_prekey_id,
            initiator_identity_ecc_public,
            initiator_identity_pqc_public,
            initiator_ephemeral_ecc_public,
            pqc_ciphertext_spk,
            pqc_ciphertext_opk,
            initial_message,
        })
    }
}
