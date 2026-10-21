use alloc::vec::Vec;
use hybrid_crypto::utils::zeroize;
use hybrid_crypto::provider::{CryptoProvider, StandardCryptoProvider as Provider};
use hybrid_crypto::hkdf::{hkdf_extract, hkdf_expand};
use crate::errors::E2EError;

use crate::state::{DoubleRatchetState, SkippedKeyState, PastEpochState};

const KDF_HASH_LEN: usize = 32;
const MAX_SKIPPED_KEYS: usize = 1000;
const MAX_HISTORICAL_DH_KEYS: usize = 20;

#[derive(Clone)]
pub struct SkippedKey {
    pub peer_dh_public: [u8; 32],
    pub message_number: u32,
    pub key: [u8; 32],
    pub iv: [u8; 12],
}

impl SkippedKey {
    #[must_use]
    pub const fn export(&self) -> SkippedKeyState {
        SkippedKeyState {
            peer_dh_public: self.peer_dh_public,
            message_number: self.message_number,
            key: self.key,
            iv: self.iv,
        }
    }

    #[must_use]
    pub const fn restore(state: &SkippedKeyState) -> Self {
        Self {
            peer_dh_public: state.peer_dh_public,
            message_number: state.message_number,
            key: state.key,
            iv: state.iv,
        }
    }
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        zeroize(&mut self.key);
        zeroize(&mut self.iv);
    }
}

#[derive(Clone)]
pub struct DoubleRatchet {
    root_key: [u8; KDF_HASH_LEN],
    
    // DH Ratchet state
    dh_send_private: [u8; 32],
    dh_send_public: [u8; 32],
    dh_recv_public: Option<[u8; 32]>,

    // PQ Ratchet state (KEM)
    kem_send_private: [u8; 2400],
    kem_send_public: [u8; 1184],
    kem_recv_public: Option<[u8; 1184]>,

    // Symmetric Ratchet state
    send_chain_key: Option<[u8; KDF_HASH_LEN]>,
    recv_chain_key: Option<[u8; KDF_HASH_LEN]>,

    send_msg_num: u32,
    recv_msg_num: u32,
    prev_send_msg_num: u32,

    // Out-of-order message key tracking
    skipped_message_keys: Vec<SkippedKey>,
    past_epochs: Vec<PastEpochState>,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        zeroize(&mut self.root_key);
        zeroize(&mut self.dh_send_private);
        zeroize(&mut self.kem_send_private);
        if let Some(mut sc) = self.send_chain_key { zeroize(&mut sc); }
        if let Some(mut rc) = self.recv_chain_key { zeroize(&mut rc); }
        self.skipped_message_keys.clear();
    }
}

impl DoubleRatchet {
    /// Initialize for Alice (Initiator). Alice already knows Bob's public keys.
    pub fn init_alice(
        root_key: [u8; 32],
        bob_dh_public: [u8; 32],
        bob_kem_public: [u8; 1184],
        entropy_dh: &[u8; 32],
        entropy_kem: &[u8; 64],
        entropy_kem_encaps: &[u8; 32],
    ) -> Result<(Self, [u8; 1088]), E2EError> {
        let (dh_send_public, dh_send_private) = Provider::x25519_generate_keypair(entropy_dh);

        let (kem_send_public, kem_send_private) = Provider::kem_generate_keypair(entropy_kem);

        let mut dr = Self {
            root_key,
            dh_send_private,
            dh_send_public,
            dh_recv_public: Some(bob_dh_public),
            kem_send_private,
            kem_send_public,
            kem_recv_public: Some(bob_kem_public),
            send_chain_key: None,
            recv_chain_key: None,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_msg_num: 0,
            skipped_message_keys: Vec::new(),
            past_epochs: Vec::new(),
        };

        // Alice immediately performs a ratchet step using Bob's public keys
        let kem_ct = dr.dh_ratchet_step_alice(entropy_kem_encaps)?;

        Ok((dr, kem_ct))
    }

    /// Initialize for Bob (Responder). Bob waits for Alice's first message to advance the ratchet.
    #[must_use]
    pub fn init_bob(
        root_key: [u8; 32],
        bob_dh_private: [u8; 32],
        bob_kem_private: [u8; 2400],
    ) -> Self {
        Self {
            root_key,
            dh_send_private: bob_dh_private,
            dh_send_public: Provider::x25519_generate_keypair(&bob_dh_private).0,
            dh_recv_public: None,
            kem_send_private: bob_kem_private,
            
            // Extract the public key from the ML-KEM private key
            kem_send_public: {
                let mut pk = [0u8; 1184];
                pk.copy_from_slice(&bob_kem_private[1152..2336]);
                pk
            },
            
            kem_recv_public: None,
            send_chain_key: None,
            recv_chain_key: None,
            send_msg_num: 0,
            recv_msg_num: 0,
            prev_send_msg_num: 0,
            skipped_message_keys: Vec::new(),
            past_epochs: Vec::new(),
        }
    }

    /// Alice performs a ratchet step locally using Bob's initial public keys, producing a KEM ciphertext to send to Bob.
    /// This happens during initialization.
    fn dh_ratchet_step_alice(&mut self, kem_entropy: &[u8; 32]) -> Result<[u8; 1088], E2EError> {
        let peer_dh_public = self.dh_recv_public.ok_or(E2EError::DoubleRatchetError)?;
        let peer_kem_public = self.kem_recv_public.ok_or(E2EError::DoubleRatchetError)?;

        // DH
        let mut dh_ss = Provider::x25519_dh(&self.dh_send_private, &peer_dh_public).map_err(|_| E2EError::DoubleRatchetError)?;
        
        // KEM Encapsulate
        let (kem_ct, mut kem_ss) = Provider::kem_encapsulate(&peer_kem_public, kem_entropy).map_err(|_| E2EError::DoubleRatchetError)?;

        // Update root key and derive SEND chain key
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&dh_ss);
        combined[32..].copy_from_slice(&kem_ss);
        zeroize(&mut dh_ss);
        zeroize(&mut kem_ss);

        let (new_root, send_chain) = self.kdf_rk(&combined);
        self.root_key = new_root;
        self.send_chain_key = Some(send_chain);
        zeroize(&mut combined);

        Ok(kem_ct)
    }

    /// Update the Double Ratchet state when receiving a new set of public keys from the peer.
    /// This is the full Hybrid Ratchet step.
    pub fn receive_ratchet_step(
        &mut self,
        peer_dh_public: &[u8; 32],
        peer_kem_public: &[u8; 1184],
        peer_kem_ciphertext: &[u8; 1088],
        my_new_dh_entropy: &[u8; 32],
        my_new_kem_entropy: &[u8; 64],
        my_new_kem_encaps_entropy: &[u8; 32],
    ) -> Result<[u8; 1088], E2EError> {
        if let Some(old_dh) = self.dh_recv_public {
            let found = self.past_epochs.iter().any(|e| e.dh_recv_public == old_dh);
            if !found {
                if let Some(old_chain_key) = self.recv_chain_key {
                    let epoch_state = PastEpochState {
                        dh_recv_public: old_dh,
                        recv_chain_key: old_chain_key,
                        recv_msg_num: self.recv_msg_num,
                    };
                    if self.past_epochs.len() >= MAX_HISTORICAL_DH_KEYS {
                        self.past_epochs.remove(0);
                    }
                    self.past_epochs.push(epoch_state);
                }
            }
        }
        
        self.dh_recv_public = Some(*peer_dh_public);
        self.kem_recv_public = Some(*peer_kem_public);
        
        self.prev_send_msg_num = self.send_msg_num;
        self.send_msg_num = 0;
        self.recv_msg_num = 0;

        // --- Step 1: Derive RECV chain ---
        // Decapsulate the ciphertext they sent to us using our current KEM private key
        let mut kem_ss_recv = Provider::kem_decapsulate(&self.kem_send_private, peer_kem_ciphertext);
        
        // Compute DH shared secret using our current DH private key and their new DH public key
        let mut dh_ss_recv = Provider::x25519_dh(&self.dh_send_private, peer_dh_public).map_err(|_| E2EError::DoubleRatchetError)?;

        let mut combined_recv = [0u8; 64];
        combined_recv[..32].copy_from_slice(&dh_ss_recv);
        combined_recv[32..].copy_from_slice(&kem_ss_recv);
        zeroize(&mut dh_ss_recv);
        zeroize(&mut kem_ss_recv);

        let (new_root_1, recv_chain) = self.kdf_rk(&combined_recv);
        self.root_key = new_root_1;
        self.recv_chain_key = Some(recv_chain);
        zeroize(&mut combined_recv);


        // --- Step 2: Generate our new keys ---
        let (dh_pub, dh_priv) = Provider::x25519_generate_keypair(my_new_dh_entropy);
        self.dh_send_private = dh_priv;
        self.dh_send_public = dh_pub;

        let (kem_send_public, kem_send_private) = Provider::kem_generate_keypair(my_new_kem_entropy);
        self.kem_send_public = kem_send_public;
        self.kem_send_private = kem_send_private;


        // --- Step 3: Derive SEND chain ---
        // Encapsulate to their new KEM public key
        let (kem_ct_send, mut kem_ss_send) = Provider::kem_encapsulate(peer_kem_public, my_new_kem_encaps_entropy).map_err(|_| E2EError::DoubleRatchetError)?;
        
        // Compute DH shared secret using our new DH private key and their new DH public key
        let mut dh_ss_send = Provider::x25519_dh(&self.dh_send_private, peer_dh_public).map_err(|_| E2EError::DoubleRatchetError)?;

        let mut combined_send = [0u8; 64];
        combined_send[..32].copy_from_slice(&dh_ss_send);
        combined_send[32..].copy_from_slice(&kem_ss_send);
        zeroize(&mut dh_ss_send);
        zeroize(&mut kem_ss_send);

        let (new_root_2, send_chain) = self.kdf_rk(&combined_send);
        self.root_key = new_root_2;
        self.send_chain_key = Some(send_chain);
        zeroize(&mut combined_send);

        // Return the ciphertext that we must send with our next message
        Ok(kem_ct_send)
    }

    /// Step the sending symmetric chain to get a message key
    pub fn next_send_message_key(&mut self) -> Result<([u8; 32], [u8; 12]), E2EError> {
        let mut chain_key = self.send_chain_key.ok_or(E2EError::DoubleRatchetError)?;
        let (next_chain, msg_key) = self.kdf_ck(&chain_key);
        self.send_chain_key = Some(next_chain);
        zeroize(&mut chain_key);
        
        let mut iv = [0u8; 12];
        hkdf_expand(&msg_key, b"IV", &mut iv);
        
        let mut enc_key = [0u8; 32];
        hkdf_expand(&msg_key, b"Key", &mut enc_key);

        self.send_msg_num += 1;
        
        // Ensure msg_key is wiped
        let mut mk = msg_key;
        zeroize(&mut mk);
        
        Ok((enc_key, iv))
    }

    /// Step the receiving symmetric chain to get a message key
    pub fn next_recv_message_key(&mut self) -> Result<([u8; 32], [u8; 12]), E2EError> {
        let mut chain_key = self.recv_chain_key.ok_or(E2EError::DoubleRatchetError)?;
        let (next_chain, msg_key) = self.kdf_ck(&chain_key);
        self.recv_chain_key = Some(next_chain);
        zeroize(&mut chain_key);
        
        let mut iv = [0u8; 12];
        hkdf_expand(&msg_key, b"IV", &mut iv);
        
        let mut enc_key = [0u8; 32];
        hkdf_expand(&msg_key, b"Key", &mut enc_key);

        self.recv_msg_num += 1;

        // Ensure msg_key is wiped
        let mut mk = msg_key;
        zeroize(&mut mk);

        Ok((enc_key, iv))
    }

    /// Skip message keys in the current receiving chain up to `until`
    pub fn skip_message_keys(&mut self, until: u32) -> Result<(), E2EError> {
        if self.recv_msg_num + 100 < until {
            // Guard against excessive skips that could crash or exhaust memory
            return Err(E2EError::DoubleRatchetError);
        }
        if let Some(mut chain_key) = self.recv_chain_key {
            let mut current_ck = chain_key;
            zeroize(&mut chain_key);
            let dh_pub = self.dh_recv_public.ok_or(E2EError::DoubleRatchetError)?;
            while self.recv_msg_num < until {
                let (next_ck, msg_key) = self.kdf_ck(&current_ck);
                zeroize(&mut current_ck);
                current_ck = next_ck;
                
                let mut iv = [0u8; 12];
                hkdf_expand(&msg_key, b"IV", &mut iv);
                
                let mut enc_key = [0u8; 32];
                hkdf_expand(&msg_key, b"Key", &mut enc_key);
                
                if self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS {
                    self.skipped_message_keys.remove(0); // Evict oldest
                }
                
                self.skipped_message_keys.push(SkippedKey {
                    peer_dh_public: dh_pub,
                    message_number: self.recv_msg_num,
                    key: enc_key,
                    iv,
                });
                
                self.recv_msg_num += 1;

                // Ensure msg_key is wiped
                let mut mk = msg_key;
                zeroize(&mut mk);
            }
            self.recv_chain_key = Some(current_ck);
        }
        Ok(())
    }

    /// Read receiving key with skipped-key support.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub fn read_recv_key(
        &mut self,
        peer_dh_public: &[u8; 32],
        message_number: u32,
        previous_chain_length: u32,
        peer_kem_public: &[u8; 1184],
        peer_kem_ciphertext: &[u8; 1088],
        my_new_dh_entropy: &[u8; 32],
        my_new_kem_entropy: &[u8; 64],
        my_new_kem_encaps_entropy: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 12], Option<[u8; 1088]>), E2EError> {
        // 1. First check skipped keys cache
        for i in 0..self.skipped_message_keys.len() {
            if self.skipped_message_keys[i].peer_dh_public == *peer_dh_public
                && self.skipped_message_keys[i].message_number == message_number
            {
                let entry = self.skipped_message_keys.remove(i);
                return Ok((entry.key, entry.iv, None));
            }
        }

        // 2. Reject if this is a historical DH key that was already ratcheted past, unless we can derive it from the history cache.
        if self.dh_recv_public != Some(*peer_dh_public) {
            let mut found_past_epoch = None;
            for i in 0..self.past_epochs.len() {
                if self.past_epochs[i].dh_recv_public == *peer_dh_public {
                    found_past_epoch = Some(i);
                    break;
                }
            }
            if let Some(idx) = found_past_epoch {
                // We found the epoch in the history cache.
                if message_number < self.past_epochs[idx].recv_msg_num {
                    return Err(E2EError::MessageOutOfOrder);
                }
                
                // Ensure we don't try to derive too many keys at once to prevent CPU DoS
                if message_number > self.past_epochs[idx].recv_msg_num + 2000 {
                    return Err(E2EError::DoubleRatchetError);
                }

                // Step the past epoch's chain key up to the message_number
                let mut current_ck = self.past_epochs[idx].recv_chain_key;
                let mut current_msg_num = self.past_epochs[idx].recv_msg_num;
                
                while current_msg_num < message_number {
                    let (next_ck, msg_key) = self.kdf_ck(&current_ck);
                    zeroize(&mut current_ck);
                    current_ck = next_ck;
                    
                    let mut iv = [0u8; 12];
                    hkdf_expand(&msg_key, b"IV", &mut iv);
                    let mut enc_key = [0u8; 32];
                    hkdf_expand(&msg_key, b"Key", &mut enc_key);
                    
                    if self.skipped_message_keys.len() >= MAX_SKIPPED_KEYS {
                        self.skipped_message_keys.remove(0); // Evict oldest
                    }
                    self.skipped_message_keys.push(SkippedKey {
                        peer_dh_public: *peer_dh_public,
                        message_number: current_msg_num,
                        key: enc_key,
                        iv,
                    });
                    current_msg_num += 1;
                    
                    let mut mk = msg_key;
                    zeroize(&mut mk);
                }
                
                // Derive the target message key
                let (next_ck, msg_key) = self.kdf_ck(&current_ck);
                zeroize(&mut current_ck);
                self.past_epochs[idx].recv_chain_key = next_ck;
                self.past_epochs[idx].recv_msg_num = current_msg_num + 1;
                
                let mut iv = [0u8; 12];
                hkdf_expand(&msg_key, b"IV", &mut iv);
                let mut enc_key = [0u8; 32];
                hkdf_expand(&msg_key, b"Key", &mut enc_key);
                
                let mut mk = msg_key;
                zeroize(&mut mk);
                
                return Ok((enc_key, iv, None));
            }
        }

        // 3. Reject if this is a past message number in the current chain
        if self.dh_recv_public == Some(*peer_dh_public) && message_number < self.recv_msg_num {
            return Err(E2EError::MessageOutOfOrder);
        }

        let mut kem_ct = None;

        // 4. Check if a new DH ratchet step is triggered
        if self.dh_recv_public != Some(*peer_dh_public) {
            // Skip remaining keys in current receive chain
            self.skip_message_keys(previous_chain_length)?;
            
            // Advance ratchet
            let ct = self.receive_ratchet_step(
                peer_dh_public,
                peer_kem_public,
                peer_kem_ciphertext,
                my_new_dh_entropy,
                my_new_kem_entropy,
                my_new_kem_encaps_entropy,
            )?;
            kem_ct = Some(ct);
        }

        // 5. Skip keys in new/current receive chain up to the message_number
        self.skip_message_keys(message_number)?;

        // 6. Compute target message key
        let (key, iv) = self.next_recv_message_key()?;

        Ok((key, iv, kem_ct))
    }

    fn kdf_rk(&self, dh_out: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
        let prk = hkdf_extract(&self.root_key, dh_out);
        
        let mut root_key = [0u8; 32];
        hkdf_expand(&prk, b"Root", &mut root_key);
        
        let mut chain_key = [0u8; 32];
        hkdf_expand(&prk, b"Chain", &mut chain_key);
        
        let mut p = prk;
        zeroize(&mut p);
        
        (root_key, chain_key)
    }

    fn kdf_ck(&self, chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let mut hmac_key = [0u8; 32];
        hkdf_expand(chain_key, b"MessageKey", &mut hmac_key);
        
        let mut next_chain = [0u8; 32];
        hkdf_expand(chain_key, b"NextChain", &mut next_chain);
        
        (next_chain, hmac_key)
    }

    #[must_use]
    pub const fn send_msg_num(&self) -> u32 { self.send_msg_num }
    #[must_use]
    pub const fn recv_msg_num(&self) -> u32 { self.recv_msg_num }
    #[must_use]
    pub const fn prev_send_msg_num(&self) -> u32 { self.prev_send_msg_num }
    
    #[must_use]
    pub const fn get_dh_send_public(&self) -> [u8; 32] { self.dh_send_public }
    #[must_use]
    pub const fn get_dh_recv_public(&self) -> Option<[u8; 32]> { self.dh_recv_public }
    #[must_use]
    pub const fn get_kem_send_public(&self) -> [u8; 1184] { self.kem_send_public }

    #[must_use]
    pub fn export(&self) -> DoubleRatchetState {
        DoubleRatchetState {
            root_key: self.root_key,
            dh_send_private: self.dh_send_private,
            dh_send_public: self.dh_send_public,
            dh_recv_public: self.dh_recv_public,
            kem_send_private: self.kem_send_private,
            kem_send_public: self.kem_send_public,
            kem_recv_public: self.kem_recv_public,
            send_chain_key: self.send_chain_key,
            recv_chain_key: self.recv_chain_key,
            send_msg_num: self.send_msg_num,
            recv_msg_num: self.recv_msg_num,
            prev_send_msg_num: self.prev_send_msg_num,
            skipped_message_keys: self.skipped_message_keys.iter().map(SkippedKey::export).collect(),
            past_epochs: self.past_epochs.clone(),
        }
    }

    #[must_use]
    pub fn restore(state: &DoubleRatchetState) -> Self {
        Self {
            root_key: state.root_key,
            dh_send_private: state.dh_send_private,
            dh_send_public: state.dh_send_public,
            dh_recv_public: state.dh_recv_public,
            kem_send_private: state.kem_send_private,
            kem_send_public: state.kem_send_public,
            kem_recv_public: state.kem_recv_public,
            send_chain_key: state.send_chain_key,
            recv_chain_key: state.recv_chain_key,
            send_msg_num: state.send_msg_num,
            recv_msg_num: state.recv_msg_num,
            prev_send_msg_num: state.prev_send_msg_num,
            skipped_message_keys: state.skipped_message_keys.iter().map(SkippedKey::restore).collect(),
            past_epochs: state.past_epochs.clone(),
        }
    }
}
