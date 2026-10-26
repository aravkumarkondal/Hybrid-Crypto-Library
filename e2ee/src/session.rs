use alloc::vec::Vec;
use crate::ratchet::DoubleRatchet;
use crate::identity::{IdentityKeyPair, IdentityPublicKey};
use crate::prekeys::{PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair};
use crate::x3dh::{HybridX3DH};
use crate::messages::{Message, MessageHeader, PreKeyMessage};
use crate::errors::E2EError;
use crate::state::SessionState;
use crate::serialization::Serialize;

#[derive(Clone)]
pub struct Session {
    ratchet: DoubleRatchet,
    pending_kem_ciphertext: Option<[u8; 1088]>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(mut kem) = self.pending_kem_ciphertext {
            hybrid_crypto::utils::zeroize(&mut kem);
        }
    }
}

impl Session {
    /// Setup a new session as the Initiator (Alice)
    #[allow(clippy::too_many_arguments)]
    pub async fn setup_as_initiator(
        my_identity: &IdentityKeyPair,
        peer_bundle: &PreKeyBundle,
        my_ecc_ephemeral_entropy: &[u8; 32],
        my_kem_entropy_spk: &[u8; 32],
        my_kem_entropy_opk: Option<&[u8; 32]>,
        ratchet_entropy_dh: &[u8; 32],
        ratchet_entropy_kem: &[u8; 64],
        ratchet_entropy_kem_encaps: &[u8; 32],
    ) -> Result<(Self, PreKeyMessage, Message), E2EError> {
        
        let x3dh_out = HybridX3DH::initiator_step(
            my_identity,
            my_ecc_ephemeral_entropy,
            my_kem_entropy_spk,
            my_kem_entropy_opk,
            peer_bundle,
        ).await?;

        let (mut ratchet, init_kem_ct) = DoubleRatchet::init_alice(
            x3dh_out.root_key,
            peer_bundle.signed_prekey_ecc_public,
            peer_bundle.signed_prekey_pqc_public,
            ratchet_entropy_dh,
            ratchet_entropy_kem,
            ratchet_entropy_kem_encaps,
        )?;

        let (key, iv) = ratchet.next_send_message_key()?;
        
        // The first message has no content, just advances the chain to let Bob init
        let header = MessageHeader {
            dh_public: ratchet.get_dh_send_public(),
            kem_public: ratchet.get_kem_send_public(),
            kem_ciphertext: init_kem_ct,
            previous_chain_length: 0,
            message_number: ratchet.send_msg_num() - 1,
        };
        
        let initial_message = Message::encrypt(
            &key,
            &iv,
            header,
            b"",
            &[],
        );

        let my_pub = my_identity.public_key().await;
        let prekey_message = PreKeyMessage {
            prekey_id: peer_bundle.one_time_prekey_id,
            signed_prekey_id: peer_bundle.signed_prekey_id,
            initiator_identity_ecc_public: my_pub.ecc_public,
            initiator_identity_pqc_public: my_pub.pqc_public,
            initiator_ephemeral_ecc_public: x3dh_out.initiator_ecc_ephemeral_public,
            pqc_ciphertext_spk: x3dh_out.pqc_ciphertext_spk,
            pqc_ciphertext_opk: x3dh_out.pqc_ciphertext_opk,
            initial_message: initial_message.clone(),
        };

        Ok((Self { ratchet, pending_kem_ciphertext: None }, prekey_message, initial_message))
    }

    /// Setup a new session as the Responder (Bob) upon receiving a `PreKeyMessage`
    pub async fn setup_as_responder(
        my_identity: &IdentityKeyPair,
        my_spk: &SignedPreKeyPair,
        my_opk: Option<&OneTimePreKeyPair>,
        prekey_msg: &PreKeyMessage,
    ) -> Result<Self, E2EError> {
        
        let x3dh_out = HybridX3DH::responder_step(
            my_identity,
            my_spk,
            my_opk,
            &prekey_msg.initiator_identity_ecc_public,
            &prekey_msg.initiator_identity_pqc_public,
            &prekey_msg.initiator_ephemeral_ecc_public,
            &prekey_msg.pqc_ciphertext_spk,
            prekey_msg.pqc_ciphertext_opk.as_ref(),
        ).await?;

        let ratchet = DoubleRatchet::init_bob(
            x3dh_out.root_key,
            my_spk.ecc_private,
            my_spk.pqc_private, // KEM private key
        );

        let session = Self { ratchet, pending_kem_ciphertext: None };
        // The first message from Alice triggers a receive ratchet step.
        // The PreKeyMessage contains an `initial_message`. 
        // We will decrypt it by providing entropy to sync the state.
        
        Ok(session)
    }

    /// Processes the initial message from the initiator to sync the Responder's ratchet state.
    /// This MUST be called immediately after `setup_as_responder` using `prekey_msg.initial_message`.
    pub fn receive_initial_message(
        &mut self,
        initial_message: &Message,
        my_new_dh_entropy: &[u8; 32],
        my_new_kem_entropy: &[u8; 64],
        my_new_kem_encaps_entropy: &[u8; 32],
    ) -> Result<Vec<u8>, E2EError> {
        self.decrypt_message(
            initial_message,
            my_new_dh_entropy,
            my_new_kem_entropy,
            my_new_kem_encaps_entropy,
        )
    }

    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
    ) -> Result<Message, E2EError> {
        let (key, iv) = self.ratchet.next_send_message_key()?;
        
        let header = MessageHeader {
            dh_public: self.ratchet.get_dh_send_public(),
            kem_public: self.ratchet.get_kem_send_public(),
            kem_ciphertext: self.pending_kem_ciphertext.unwrap_or([0u8; 1088]),
            previous_chain_length: self.ratchet.prev_send_msg_num(),
            message_number: self.ratchet.send_msg_num() - 1,
        };

        Ok(Message::encrypt(&key, &iv, header, plaintext, &[]))
    }

    pub fn decrypt_message(
        &mut self,
        message: &Message,
        my_new_dh_entropy: &[u8; 32],
        my_new_kem_entropy: &[u8; 64],
        my_new_kem_encaps_entropy: &[u8; 32],
    ) -> Result<Vec<u8>, E2EError> {
        let saved_ratchet = self.ratchet.clone();
        let saved_pending = self.pending_kem_ciphertext;

        let (key, iv, new_kem_ct) = match self.ratchet.read_recv_key(
            &message.header.dh_public,
            message.header.message_number,
            message.header.previous_chain_length,
            &message.header.kem_public,
            &message.header.kem_ciphertext,
            my_new_dh_entropy,
            my_new_kem_entropy,
            my_new_kem_encaps_entropy,
        ) {
            Ok(res) => res,
            Err(e) => {
                self.ratchet = saved_ratchet;
                self.pending_kem_ciphertext = saved_pending;
                return Err(e);
            }
        };

        if let Some(ct) = new_kem_ct {
            self.pending_kem_ciphertext = Some(ct);
        }

        match message.decrypt(&key, &iv, &[]) {
            Ok(plaintext) => Ok(plaintext.to_vec()),
            Err(e) => {
                self.ratchet = saved_ratchet;
                self.pending_kem_ciphertext = saved_pending;
                Err(e)
            }
        }
    }

    pub fn export_state(&self, master_key: &[u8; 32]) -> Vec<u8> {
        let state = SessionState::new(
            self.ratchet.export(),
            self.pending_kem_ciphertext,
        );
        state.serialize_secure(master_key)
    }

    pub fn restore_state(data: &[u8], master_key: &[u8; 32]) -> Result<Self, E2EError> {
        let state = SessionState::deserialize_secure(data, master_key)?;
        Ok(Self {
            ratchet: DoubleRatchet::restore(&state.ratchet),
            pending_kem_ciphertext: state.pending_kem_ciphertext,
        })
    }
}

/// A collection of sessions representing connections to multiple devices of a single contact.
#[derive(Clone)]
pub struct MultiDeviceSession {
    pub account_identity: IdentityPublicKey,
    pub sessions: Vec<(u32, Session)>,
}

impl MultiDeviceSession {
    #[must_use]
    pub const fn new(account_identity: IdentityPublicKey) -> Self {
        Self {
            account_identity,
            sessions: Vec::new(),
        }
    }

    pub fn add_session(&mut self, device_id: u32, session: Session) {
        // Replace if exists
        if let Some(existing) = self.sessions.iter_mut().find(|(id, _)| *id == device_id) {
            existing.1 = session;
        } else {
            self.sessions.push((device_id, session));
        }
    }

    pub fn get_session_mut(&mut self, device_id: u32) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|(id, _)| *id == device_id).map(|(_, s)| s)
    }
    
    #[must_use]
    pub fn get_session(&self, device_id: u32) -> Option<&Session> {
        self.sessions.iter().find(|(id, _)| *id == device_id).map(|(_, s)| s)
    }

    pub fn remove_session(&mut self, device_id: u32) {
        self.sessions.retain(|(id, _)| *id != device_id);
    }
}

impl Serialize for MultiDeviceSession {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let identity_bytes = self.account_identity.serialize();
        out.extend_from_slice(&(identity_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&identity_bytes);

        out.extend_from_slice(&(self.sessions.len() as u32).to_le_bytes());
        for (device_id, session) in &self.sessions {
            out.extend_from_slice(&device_id.to_le_bytes());
            
            let master_key = [0x55; 32];
            let session_bytes = session.export_state(&master_key);
            out.extend_from_slice(&(session_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&session_bytes);
        }

        out
    }

    fn deserialize(data: &[u8]) -> Result<Self, E2EError> {
        let mut offset = 0;
        if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let mut b = [0u8; 4];
        b.copy_from_slice(&data[offset..offset+4]);
        let id_len = u32::from_le_bytes(b) as usize;
        offset += 4;

        if offset + id_len > data.len() { return Err(E2EError::InvalidMessageFormat); }
        let account_identity = IdentityPublicKey::deserialize(&data[offset..offset+id_len])?;
        offset += id_len;

        if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
        b.copy_from_slice(&data[offset..offset+4]);
        let sessions_len = u32::from_le_bytes(b) as usize;
        offset += 4;

        // Arbitrary limit to prevent DoS
        if sessions_len > 1000 { return Err(E2EError::InvalidMessageFormat); }

        let mut sessions = Vec::with_capacity(sessions_len);
        for _ in 0..sessions_len {
            if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            b.copy_from_slice(&data[offset..offset+4]);
            let device_id = u32::from_le_bytes(b);
            offset += 4;

            if offset + 4 > data.len() { return Err(E2EError::InvalidMessageFormat); }
            b.copy_from_slice(&data[offset..offset+4]);
            let session_bytes_len = u32::from_le_bytes(b) as usize;
            offset += 4;

            if offset + session_bytes_len > data.len() { return Err(E2EError::InvalidMessageFormat); }
            let master_key = [0x55; 32];
            let session = Session::restore_state(&data[offset..offset+session_bytes_len], &master_key)?;
            sessions.push((device_id, session));
            offset += session_bytes_len;
        }

        Ok(Self {
            account_identity,
            sessions,
        })
    }
}

