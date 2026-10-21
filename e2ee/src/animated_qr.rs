use alloc::vec::Vec;
use crate::errors::E2EError;
use hybrid_crypto::sha2::Sha256;

/// Represents a single frame in an animated QR sequence.
#[derive(Clone, Debug)]
pub struct QrFrame {
    pub sequence_num: u16,
    pub total_frames: u16,
    /// SHA256 Hash of the *complete* reassembled payload.
    /// This prevents an attacker from combining valid frames from different payloads.
    pub payload_hash: [u8; 32],
    /// SHA256 Hash of this specific chunk data.
    pub chunk_hash: [u8; 32],
    /// The actual payload chunk for this frame.
    pub chunk_data: Vec<u8>,
}

impl QrFrame {
    /// Serializes a `QrFrame` into bytes for QR encoding.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.sequence_num.to_be_bytes());
        out.extend_from_slice(&self.total_frames.to_be_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&self.chunk_hash);
        out.extend_from_slice(&(self.chunk_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.chunk_data);
        out
    }

    /// Deserializes bytes back into a `QrFrame`.
    pub fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut offset = 0;
        
        if offset + 2 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let mut b2 = [0u8; 2];
        b2.copy_from_slice(&data[offset..offset+2]);
        let sequence_num = u16::from_be_bytes(b2);
        offset += 2;

        if offset + 2 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        b2.copy_from_slice(&data[offset..offset+2]);
        let total_frames = u16::from_be_bytes(b2);
        offset += 2;

        if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 32 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let mut chunk_hash = [0u8; 32];
        chunk_hash.copy_from_slice(&data[offset..offset+32]);
        offset += 32;

        if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let mut b4 = [0u8; 4];
        b4.copy_from_slice(&data[offset..offset+4]);
        let chunk_len = u32::from_be_bytes(b4) as usize;
        offset += 4;

        if offset + chunk_len > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let chunk_data = data[offset..offset+chunk_len].to_vec();

        // Verify chunk integrity immediately upon deserialization
        let mut hasher = Sha256::new();
        hasher.update(&chunk_data);
        if hasher.finalize() != chunk_hash {
            return Err(E2EError::InvalidMessageFormat); // Corrupted chunk
        }

        Ok(Self {
            sequence_num,
            total_frames,
            payload_hash,
            chunk_hash,
            chunk_data,
        })
    }
}

/// Splits a large payload into a sequence of `QrFrames`.
#[must_use]
pub fn encode_animated_qr(payload: &[u8], chunk_size: usize) -> Vec<QrFrame> {
    let mut frames = Vec::new();
    let total_frames = payload.len().div_ceil(chunk_size);
    
    let mut payload_hasher = Sha256::new();
    payload_hasher.update(payload);
    let payload_hash = payload_hasher.finalize();

    for i in 0..total_frames {
        let start = i * chunk_size;
        let end = core::cmp::min(start + chunk_size, payload.len());
        let chunk = payload[start..end].to_vec();

        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(&chunk);
        let chunk_hash = chunk_hasher.finalize();

        frames.push(QrFrame {
            sequence_num: i as u16,
            total_frames: total_frames as u16,
            payload_hash,
            chunk_hash,
            chunk_data: chunk,
        });
    }

    frames
}

/// Accumulates frames and reconstructs the original payload.
pub struct QrAssembler {
    expected_frames: Option<u16>,
    expected_payload_hash: Option<[u8; 32]>,
    frames: Vec<Option<Vec<u8>>>,
    received_count: u16,
}

impl Default for QrAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl QrAssembler {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected_frames: None,
            expected_payload_hash: None,
            frames: Vec::new(),
            received_count: 0,
        }
    }

    /// Adds a frame to the accumulator.
    /// Returns `Ok(Some(payload))` if the payload is completely assembled and verified.
    /// Returns `Ok(None)` if more frames are needed.
    pub fn add_frame(&mut self, frame: QrFrame) -> Result<Option<Vec<u8>>, E2EError> {
        // Initialize state on first frame
        if self.expected_frames.is_none() {
            self.expected_frames = Some(frame.total_frames);
            self.expected_payload_hash = Some(frame.payload_hash);
            self.frames = alloc::vec![None; frame.total_frames as usize];
        }

        // Sequence validation
        let total = self.expected_frames.unwrap();
        if frame.total_frames != total || frame.sequence_num >= total {
            return Err(E2EError::InvalidMessageFormat);
        }

        // Payload hash consistency validation (prevents mixing frames from different payloads)
        if frame.payload_hash != self.expected_payload_hash.unwrap() {
            return Err(E2EError::InvalidMessageFormat);
        }

        // Duplicate handling
        if self.frames[frame.sequence_num as usize].is_some() {
            return Ok(None); // Already have this frame, safely ignore
        }

        // Insert frame
        self.frames[frame.sequence_num as usize] = Some(frame.chunk_data);
        self.received_count += 1;

        // Check if complete
        if self.received_count == total {
            let mut payload = Vec::new();
            for f in &self.frames {
                payload.extend_from_slice(f.as_ref().unwrap());
            }

            // Final Payload Authentication Check
            let mut hasher = Sha256::new();
            hasher.update(&payload);
            if hasher.finalize() != self.expected_payload_hash.unwrap() {
                return Err(E2EError::InvalidMessageFormat); // Entire payload verification failed
            }

            return Ok(Some(payload));
        }

        Ok(None)
    }
}
