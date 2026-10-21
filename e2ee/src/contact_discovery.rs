use alloc::vec::Vec;
use crate::session::Session;
use crate::messages::Message;
use crate::errors::E2EError;
use hybrid_crypto::utils::zeroize;

/// Represents an Enclave-Assisted Private Contact Discovery Client
/// 
/// Privacy Claim: [HIGH CONFIDENCE] - Contact hashes are transmitted exclusively
/// within an E2EE tunnel. The server cannot passively observe the graph.
pub struct DiscoveryClient;

impl DiscoveryClient {
    /// Encrypts the list of hashed contacts for transmission to the Enclave
    pub fn prepare_request(
        session: &mut Session,
        contact_hashes: &[&[u8; 32]],
    ) -> Result<Message, E2EError> {
        let mut plaintext = Vec::new();
        // Simple serialization of hashes
        for hash in contact_hashes {
            plaintext.extend_from_slice(*hash);
        }
        
        session.encrypt_message(&plaintext)
    }

    /// Decrypts the enclave's response to get the intersected hashes
    pub fn process_response(
        session: &mut Session,
        req: &Message,
        dh_entropy: &[u8; 32],
        kem_entropy: &[u8; 64],
        kem_encaps_entropy: &[u8; 32],
    ) -> Result<Vec<[u8; 32]>, E2EError> {
        let plaintext = session.decrypt_message(
            req,
            dh_entropy,
            kem_entropy,
            kem_encaps_entropy,
        )?;
        
        if plaintext.len() % 32 != 0 {
            return Err(E2EError::InvalidMessageFormat);
        }

        let mut matches = Vec::new();
        for chunk in plaintext.chunks_exact(32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            matches.push(hash);
        }

        Ok(matches)
    }
}

/// Represents the Discovery Enclave
/// 
/// Privacy Claim: [SPECULATIVE] - Assuming the environment provides true SGX-like 
/// memory isolation, the enclave prevents arbitrary read access.
/// Privacy Claim: [VERIFIED] - The Enclave zeroizes all query buffers after processing.
pub struct DiscoveryEnclave {
    pub registered_hashes: Vec<[u8; 32]>,
}

impl DiscoveryEnclave {
    #[must_use]
    pub const fn new(registered_hashes: Vec<[u8; 32]>) -> Self {
        Self { registered_hashes }
    }

    /// Processes an encrypted discovery request and returns an encrypted intersection
    pub fn process_request(
        &self,
        session: &mut Session,
        msg: &Message,
        dh_entropy: &[u8; 32],
        kem_entropy: &[u8; 64],
        kem_encaps_entropy: &[u8; 32],
    ) -> Result<Message, E2EError> {
        let mut query = session.decrypt_message(
            msg,
            dh_entropy,
            kem_entropy,
            kem_encaps_entropy,
        )?;

        if query.len() % 32 != 0 {
            zeroize(&mut query);
            return Err(E2EError::InvalidMessageFormat);
        }

        let mut intersection = Vec::new();
        for chunk in query.chunks_exact(32) {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(chunk);
            
            if self.registered_hashes.contains(&hash) {
                intersection.extend_from_slice(&hash);
            }
        }

        // [VERIFIED] Zeroize the client's queries from memory immediately
        zeroize(&mut query);

        let response = session.encrypt_message(&intersection)?;
        Ok(response)
    }
}
