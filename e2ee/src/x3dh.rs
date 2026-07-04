use alloc::vec::Vec;
use hybrid_crypto::utils::zeroize;
use hybrid_crypto::x25519::{x25519, x25519_base};
use hybrid_crypto::ml_kem::{ml_kem_768_encapsulate, ml_kem_768_decapsulate};
use hybrid_crypto::hkdf::{hkdf_extract, hkdf_expand};
use crate::identity::IdentityKeyPair;
use crate::prekeys::{PreKeyBundle, SignedPreKeyPair, OneTimePreKeyPair};
use crate::errors::E2EError;

pub struct HybridX3DH;

pub struct InitiatorOutput {
    pub root_key: [u8; 32],
    pub initiator_ecc_ephemeral_public: [u8; 32],
    pub pqc_ciphertext_spk: [u8; 1088],
    pub pqc_ciphertext_opk: Option<[u8; 1088]>,
}

pub struct ResponderOutput {
    pub root_key: [u8; 32],
}

impl HybridX3DH {
    /// Initiator performs X3DH to compute the initial root key.
    /// Returns the root key and the ephemeral data that must be sent to the responder.
    pub fn initiator_step(
        initiator_identity: &IdentityKeyPair,
        initiator_ecc_ephemeral_entropy: &[u8; 32],
        pqc_entropy_spk: &[u8; 32],
        pqc_entropy_opk: Option<&[u8; 32]>,
        responder_bundle: &PreKeyBundle,
    ) -> Result<InitiatorOutput, E2EError> {
        responder_bundle.verify_signature()?;

        let ek_a = *initiator_ecc_ephemeral_entropy;
        let ek_a_pub = x25519_base(&ek_a);

        // DH1 = DH(IK_A, SPK_B)
        let mut dh1 = x25519(&initiator_identity.ecc_private, &responder_bundle.signed_prekey_ecc_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;
        
        // DH2 = DH(EK_A, IK_B)
        let mut dh2 = x25519(&ek_a, &responder_bundle.identity_key.ecc_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;

        // DH3 = DH(EK_A, SPK_B)
        let mut dh3 = x25519(&ek_a, &responder_bundle.signed_prekey_ecc_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;

        // PQ1 = Encaps(SPK_B_PQC)
        let (pqc_ciphertext_spk, mut pq_ss1) = ml_kem_768_encapsulate(
            &responder_bundle.signed_prekey_pqc_public,
            pqc_entropy_spk,
        ).map_err(|_| E2EError::InvalidPreKeyBundle)?;

        // KDF Context
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&[0xFF; 32]);
        kdf_input.extend_from_slice(&dh1);
        kdf_input.extend_from_slice(&dh2);
        kdf_input.extend_from_slice(&dh3);
        
        let mut pqc_ciphertext_opk = None;

        if let Some(opk_ecc) = &responder_bundle.one_time_prekey_ecc_public {
            if let Some(opk_pqc) = &responder_bundle.one_time_prekey_pqc_public {
                let ent_opk = pqc_entropy_opk.ok_or(E2EError::MissingOneTimePreKey)?;
                
                // DH4 = DH(EK_A, OPK_B)
                let mut dh4 = x25519(&ek_a, opk_ecc).map_err(|_| E2EError::InvalidPreKeyBundle)?;
                kdf_input.extend_from_slice(&dh4);
                zeroize(&mut dh4);

                // PQ2 = Encaps(OPK_B_PQC)
                let (ct_opk, mut pq_ss2) = ml_kem_768_encapsulate(opk_pqc, ent_opk)
                    .map_err(|_| E2EError::InvalidPreKeyBundle)?;
                
                kdf_input.extend_from_slice(&pq_ss2);
                pqc_ciphertext_opk = Some(ct_opk);
                zeroize(&mut pq_ss2);
            }
        }

        kdf_input.extend_from_slice(&pq_ss1);

        zeroize(&mut dh1);
        zeroize(&mut dh2);
        zeroize(&mut dh3);
        zeroize(&mut pq_ss1);

        let prk = hkdf_extract(&[], &kdf_input);
        zeroize(&mut kdf_input);

        let mut root_key = [0u8; 32];
        hkdf_expand(&prk, b"X3DH-PQ-Root", &mut root_key);

        Ok(InitiatorOutput {
            root_key,
            initiator_ecc_ephemeral_public: ek_a_pub,
            pqc_ciphertext_spk,
            pqc_ciphertext_opk,
        })
    }

    /// Responder computes the root key from the initiator's ephemeral data.
    pub fn responder_step(
        responder_identity: &IdentityKeyPair,
        responder_spk: &SignedPreKeyPair,
        responder_opk: Option<&OneTimePreKeyPair>,
        initiator_identity_ecc_pub: &[u8; 32],
        initiator_ecc_ephemeral_public: &[u8; 32],
        pqc_ciphertext_spk: &[u8; 1088],
        pqc_ciphertext_opk: Option<&[u8; 1088]>,
    ) -> Result<ResponderOutput, E2EError> {
        
        let ik_a = initiator_identity_ecc_pub;
        let ek_a = initiator_ecc_ephemeral_public;

        // DH1 = DH(SPK_B, IK_A)
        let mut dh1 = x25519(&responder_spk.ecc_private, ik_a)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;
        
        // DH2 = DH(IK_B, EK_A)
        let mut dh2 = x25519(&responder_identity.ecc_private, ek_a)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;
        
        // DH3 = DH(SPK_B, EK_A)
        let mut dh3 = x25519(&responder_spk.ecc_private, ek_a)
            .map_err(|_| E2EError::InvalidPreKeyBundle)?;
            
        // PQ1 = Decaps(SPK_B_PQC, CT_SPK)
        let mut pq_ss1 = ml_kem_768_decapsulate(&responder_spk.pqc_private, pqc_ciphertext_spk);

        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(&[0xFF; 32]);
        kdf_input.extend_from_slice(&dh1);
        kdf_input.extend_from_slice(&dh2);
        kdf_input.extend_from_slice(&dh3);

        if let Some(opk) = responder_opk {
            if let Some(ct_opk) = pqc_ciphertext_opk {
                // DH4 = DH(OPK_B, EK_A)
                let mut dh4 = x25519(&opk.ecc_private, ek_a).map_err(|_| E2EError::InvalidPreKeyBundle)?;
                kdf_input.extend_from_slice(&dh4);
                zeroize(&mut dh4);

                // PQ2 = Decaps(OPK_B_PQC, CT_OPK)
                let mut pq_ss2 = ml_kem_768_decapsulate(&opk.pqc_private, ct_opk);
                kdf_input.extend_from_slice(&pq_ss2);
                zeroize(&mut pq_ss2);
            }
        }

        kdf_input.extend_from_slice(&pq_ss1);

        zeroize(&mut dh1);
        zeroize(&mut dh2);
        zeroize(&mut dh3);
        zeroize(&mut pq_ss1);

        let prk = hkdf_extract(&[], &kdf_input);
        zeroize(&mut kdf_input);

        let mut root_key = [0u8; 32];
        hkdf_expand(&prk, b"X3DH-PQ-Root", &mut root_key);

        Ok(ResponderOutput {
            root_key,
        })
    }
}
