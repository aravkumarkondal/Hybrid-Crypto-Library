use alloc::vec::Vec;
use crate::errors::E2EError;

pub const TYPE_BODY: u8 = 0x01;
pub const TYPE_EXPIRES_AT: u8 = 0x02;
pub const TYPE_ATTACHMENT: u8 = 0x03;
pub const TYPE_PADDING: u8 = 0xFF;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub attachment_id: [u8; 16],
    pub aes_key: [u8; 32],
    pub iv: [u8; 12],
    pub sha256_hash: [u8; 32],
}

impl Attachment {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 32 + 12 + 32);
        out.extend_from_slice(&self.attachment_id);
        out.extend_from_slice(&self.aes_key);
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.sha256_hash);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, E2EError> {
        if data.len() != 92 {
            return Err(E2EError::InvalidMessageFormat);
        }
        let mut attachment_id = [0u8; 16];
        let mut aes_key = [0u8; 32];
        let mut iv = [0u8; 12];
        let mut sha256_hash = [0u8; 32];
        
        attachment_id.copy_from_slice(&data[0..16]);
        aes_key.copy_from_slice(&data[16..48]);
        iv.copy_from_slice(&data[48..60]);
        sha256_hash.copy_from_slice(&data[60..92]);

        Ok(Self { attachment_id, aes_key, iv, sha256_hash })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MessagePayload {
    pub body: Vec<u8>,
    pub expires_at: Option<u64>,
    pub attachments: Vec<Attachment>,
}

impl MessagePayload {
    #[must_use]
    pub fn new(body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            expires_at: None,
            attachments: Vec::new(),
        }
    }

    #[must_use]
    pub fn serialize(&self, pad_to_block: Option<usize>) -> Vec<u8> {
        let mut out = Vec::new();
        
        // 1. Serialize Body
        if !self.body.is_empty() {
            out.push(TYPE_BODY);
            let len = self.body.len() as u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&self.body);
        }

        // 2. Serialize Expiration
        if let Some(exp) = self.expires_at {
            out.push(TYPE_EXPIRES_AT);
            let len = 8u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&exp.to_le_bytes());
        }

        // 3. Serialize Attachments
        for att in &self.attachments {
            let att_bytes = att.to_bytes();
            out.push(TYPE_ATTACHMENT);
            let len = att_bytes.len() as u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&att_bytes);
        }

        // 4. Padding
        if let Some(block_size) = pad_to_block {
            let current_len = out.len();
            let remainder = current_len % block_size;
            let mut pad_len = block_size - remainder;
            
            // TLV needs 5 bytes (1 byte type + 4 bytes length)
            if pad_len < 5 {
                pad_len += block_size;
            }
            
            let pad_val_len = pad_len - 5;
            out.push(TYPE_PADDING);
            out.extend_from_slice(&(pad_val_len as u32).to_le_bytes());
            
            let padding = alloc::vec![0u8; pad_val_len];
            // Since AES-256-GCM provides CPA security, padding with zeros is perfectly fine for length hiding
            out.extend_from_slice(&padding);
        }

        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut payload = Self {
            body: Vec::new(),
            expires_at: None,
            attachments: Vec::new(),
        };

        let mut offset = 0;
        while offset < data.len() {
            if offset + 5 > data.len() {
                return Err(E2EError::InvalidMessageFormat); // Needs at least 1 byte type + 4 bytes length
            }

            let t = data[offset];
            
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&data[offset + 1..offset + 5]);
            let len = u32::from_le_bytes(len_bytes) as usize;
            
            offset += 5;

            if offset + len > data.len() {
                return Err(E2EError::InvalidMessageFormat);
            }

            let val = &data[offset..offset + len];

            match t {
                TYPE_BODY => {
                    payload.body = val.to_vec();
                }
                TYPE_EXPIRES_AT => {
                    if len != 8 {
                        return Err(E2EError::InvalidMessageFormat);
                    }
                    let mut exp_bytes = [0u8; 8];
                    exp_bytes.copy_from_slice(val);
                    payload.expires_at = Some(u64::from_le_bytes(exp_bytes));
                }
                TYPE_ATTACHMENT => {
                    let att = Attachment::from_bytes(val)?;
                    payload.attachments.push(att);
                }
                _ => {
                    // Unknown types can be ignored for forward compatibility
                }
            }

            offset += len;
        }

        Ok(payload)
    }
}
