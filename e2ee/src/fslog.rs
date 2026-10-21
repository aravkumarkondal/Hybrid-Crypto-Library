use alloc::vec::Vec;
use crate::errors::E2EError;
use hybrid_crypto::hkdf::hkdf_expand;
use hybrid_crypto::sha2::Sha256;
use hybrid_crypto::aes_gcm::{aes256_gcm_encrypt, aes256_gcm_decrypt};
use hybrid_crypto::utils::zeroize;
use alloc::vec;

pub const LOG_VERSION: u8 = 1;
pub const LOG_FORMAT_IDENTIFIER: u16 = 0x4653; // 'FS'

/// A plaintext audit log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub version: u8,
    pub format_id: u16,
    pub sequence_num: u64,
    pub timestamp: u64, // 0 if unavailable
    pub payload: Vec<u8>,
}

impl LogEntry {
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.format_id.to_be_bytes());
        out.extend_from_slice(&self.sequence_num.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        if data.len() < 19 {
            return Err(E2EError::InvalidMessageFormat);
        }
        let version = data[0];
        
        let mut b2 = [0u8; 2];
        b2.copy_from_slice(&data[1..3]);
        let format_id = u16::from_be_bytes(b2);
        
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&data[3..11]);
        let sequence_num = u64::from_be_bytes(b8);
        
        b8.copy_from_slice(&data[11..19]);
        let timestamp = u64::from_be_bytes(b8);
        
        let payload = data[19..].to_vec();
        
        Ok(Self {
            version,
            format_id,
            sequence_num,
            timestamp,
            payload,
        })
    }
}

/// An encrypted, tamper-evident log entry.
#[derive(Clone)]
pub struct EncryptedLogEntry {
    pub sequence_num: u64,
    pub ciphertext: Vec<u8>,
    pub current_hash: [u8; 32],
}

pub struct FsLogStore {
    current_key: [u8; 32],
    current_hash: [u8; 32],
    sequence_num: u64,
    pub entries: Vec<EncryptedLogEntry>,
}

impl Drop for FsLogStore {
    fn drop(&mut self) {
        zeroize(&mut self.current_key);
    }
}

impl FsLogStore {
    /// Initializes a new log with a genesis key and an optional genesis hash (usually all zeros).
    #[must_use]
    pub const fn new(genesis_key: &[u8; 32], genesis_hash: &[u8; 32]) -> Self {
        Self {
            current_key: *genesis_key,
            current_hash: *genesis_hash,
            sequence_num: 0,
            entries: Vec::new(),
        }
    }

    /// Evolves the forward-secure key for the next entry
    fn evolve_key(key: &mut [u8; 32]) {
        let mut next_key = [0u8; 32];
        hkdf_expand(key, b"FSLOG_EVOLVE", &mut next_key);
        zeroize(key);
        *key = next_key;
    }

    /// Appends a new event to the log.
    pub fn append(&mut self, payload: &[u8], timestamp: u64) -> Result<(), E2EError> {
        let entry = LogEntry {
            version: LOG_VERSION,
            format_id: LOG_FORMAT_IDENTIFIER,
            sequence_num: self.sequence_num,
            timestamp,
            payload: payload.to_vec(),
        };

        let pt = entry.serialize();
        
        // Use the sequence number to derive a unique IV for this encryption
        let mut iv = [0u8; 12];
        let seq_bytes = self.sequence_num.to_be_bytes();
        iv[4..12].copy_from_slice(&seq_bytes);
        
        let mut ciphertext = vec![0u8; pt.len()];
        let tag = aes256_gcm_encrypt(&self.current_key, &iv, &[], &pt, &mut ciphertext);
            
        let mut full_ct = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
        full_ct.extend_from_slice(&iv);
        full_ct.extend_from_slice(&tag);
        full_ct.extend_from_slice(&ciphertext);

        // H_{i} = SHA256(H_{i-1} || E_i)
        let mut hasher = Sha256::new();
        hasher.update(&self.current_hash);
        hasher.update(&full_ct);
        let next_hash = hasher.finalize();

        self.entries.push(EncryptedLogEntry {
            sequence_num: self.sequence_num,
            ciphertext: full_ct,
            current_hash: next_hash,
        });

        self.current_hash = next_hash;
        self.sequence_num += 1;
        Self::evolve_key(&mut self.current_key);
        
        Ok(())
    }

    /// Verifies an entire log chain from a starting state.
    /// Returns the decrypted log entries if verification is successful.
    pub fn verify_log_chain(
        genesis_key: &[u8; 32],
        genesis_hash: &[u8; 32],
        entries: &[EncryptedLogEntry],
    ) -> Result<Vec<LogEntry>, E2EError> {
        let mut current_key = *genesis_key;
        let mut current_hash = *genesis_hash;
        let mut expected_seq = 0;
        let mut decoded_entries = Vec::new();

        for enc_entry in entries {
            // 1. Verify Entry Ordering & Sequence Continuity
            if enc_entry.sequence_num != expected_seq {
                return Err(E2EError::InvalidMessageFormat);
            }

            // 2. Verify Hash Chain Integrity
            let mut hasher = Sha256::new();
            hasher.update(&current_hash);
            hasher.update(&enc_entry.ciphertext);
            if hasher.finalize() != enc_entry.current_hash {
                return Err(E2EError::InvalidSignature); // Hash chain broken
            }
            current_hash = enc_entry.current_hash;

            // 3. Verify Ciphertext Integrity and Decrypt
            if enc_entry.ciphertext.len() < 28 { // 12 IV + 16 Tag
                return Err(E2EError::InvalidMessageFormat);
            }
            let iv = &enc_entry.ciphertext[0..12];
            let tag = &enc_entry.ciphertext[12..28];
            let ct = &enc_entry.ciphertext[28..];
            
            let mut pt = vec![0u8; ct.len()];
            let mut iv_arr = [0u8; 12];
            iv_arr.copy_from_slice(iv);
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(tag);
            
            aes256_gcm_decrypt(&current_key, &iv_arr, &[], ct, &tag_arr, &mut pt)
                .map_err(|_| E2EError::MessageDecryptionFailed)?;
                
            let dec_entry = LogEntry::deserialize(&pt)?;

            // 4. Verify Version Consistency & Format
            if dec_entry.version != LOG_VERSION || dec_entry.format_id != LOG_FORMAT_IDENTIFIER {
                return Err(E2EError::InvalidMessageFormat);
            }
            if dec_entry.sequence_num != expected_seq {
                return Err(E2EError::InvalidMessageFormat); // Inner sequence doesn't match outer
            }

            decoded_entries.push(dec_entry);

            // Evolve key for next entry
            Self::evolve_key(&mut current_key);
            expected_seq += 1;
        }

        // Ensure current_key is wiped
        zeroize(&mut current_key);

        Ok(decoded_entries)
    }
}
