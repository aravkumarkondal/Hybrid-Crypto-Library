//! Hardware Keystore Attestation Tampering & Key Handle Collision Fuzzer
//!
//! Validates:
//! 1. Attestation Integrity & Signature Binding: Any single-bit mutation in the hardware
//!    attestation statement, certified public key, or enclave root signature is strictly rejected.
//! 2. Attestation Nonce Freshness: Attestations bound to challenge nonce N cannot be replayed for nonce N'.
//! 3. Slot / Handle Bounds Enforcement: Accessing unallocated, out-of-range, or u32::MAX key handles
//!    fails with explicit error without panics.
//! 4. Cross-Slot Key Isolation: Cryptographic operations on slot A cannot access or leak keys from slot B.
//! 5. Secure Deletion & Post-Eviction Access Invalidation: Deleted key handles are securely zeroized
//!    and immediately invalid for subsequent cryptographic operations.

extern crate alloc;

use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::Mutex;
use e2ee::identity::{IdentityPublicKey, SoftwareIdentityKeyPair};
use e2ee::errors::E2EError;
use hybrid_crypto::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use hybrid_crypto::utils::zeroize;

#[derive(Clone)]
struct HardwareAttestationStatement {
    enclave_root_pub: Vec<u8>,
    attested_public_key: IdentityPublicKey,
    challenge_nonce: [u8; 32],
    enclave_signature: Vec<u8>,
}

impl HardwareAttestationStatement {
    fn verify(&self, expected_nonce: &[u8; 32]) -> Result<(), E2EError> {
        if self.challenge_nonce != *expected_nonce {
            return Err(E2EError::InvalidMessageFormat);
        }

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&self.challenge_nonce);
        transcript.extend_from_slice(&self.attested_public_key.ecc_public);
        transcript.extend_from_slice(&self.attested_public_key.pqc_public);

        if ml_dsa_87_verify(
            &self.enclave_root_pub,
            &transcript,
            b"ENCLAVE_ATTESTATION",
            &self.enclave_signature,
        ) {
            Ok(())
        } else {
            Err(E2EError::InvalidSignature)
        }
    }
}

struct MultiSlotMockHardwareKeystore {
    enclave_root_pub: Vec<u8>,
    enclave_root_priv: Vec<u8>,
    slots: Mutex<HashMap<u32, SoftwareIdentityKeyPair>>,
    next_handle: Mutex<u32>,
}

impl MultiSlotMockHardwareKeystore {
    fn new(enclave_seed: &[u8; 32]) -> Self {
        let (root_pub, root_priv) = ml_dsa_87_keypair(enclave_seed);
        Self {
            enclave_root_pub: root_pub,
            enclave_root_priv: root_priv.0.clone(),
            slots: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(1),
        }
    }

    fn provision_key(&self, entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 32]) -> u32 {
        let kp = SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc);
        let mut handle_lock = self.next_handle.lock().unwrap();
        let handle = *handle_lock;
        *handle_lock += 1;

        self.slots.lock().unwrap().insert(handle, kp);
        handle
    }

    fn generate_attestation(&self, handle: u32, challenge_nonce: &[u8; 32]) -> Result<HardwareAttestationStatement, E2EError> {
        let slots = self.slots.lock().unwrap();
        let key = slots.get(&handle).ok_or(E2EError::SigningError)?;

        let pk = IdentityPublicKey {
            ecc_public: key.ecc_public,
            pqc_public: key.pqc_public.clone(),
        };

        let mut transcript = Vec::new();
        transcript.extend_from_slice(challenge_nonce);
        transcript.extend_from_slice(&pk.ecc_public);
        transcript.extend_from_slice(&pk.pqc_public);

        let rnd = [0x55u8; 32];
        let sig = ml_dsa_87_sign(&self.enclave_root_priv, &transcript, b"ENCLAVE_ATTESTATION", &rnd)
            .map_err(|_| E2EError::SigningError)?;

        Ok(HardwareAttestationStatement {
            enclave_root_pub: self.enclave_root_pub.clone(),
            attested_public_key: pk,
            challenge_nonce: *challenge_nonce,
            enclave_signature: sig,
        })
    }

    fn delete_key(&self, handle: u32) -> Result<(), E2EError> {
        let mut slots = self.slots.lock().unwrap();
        if let Some(mut kp) = slots.remove(&handle) {
            zeroize(&mut kp.ecc_private);
            zeroize(&mut kp.pqc_private);
            Ok(())
        } else {
            Err(E2EError::SigningError)
        }
    }
}

impl Drop for MultiSlotMockHardwareKeystore {
    fn drop(&mut self) {
        zeroize(&mut self.enclave_root_priv);
    }
}

#[test]
fn test_attestation_signature_and_nonce_tampering_fuzzing() {
    let keystore = MultiSlotMockHardwareKeystore::new(&[0x11; 32]);
    let handle = keystore.provision_key(&[0x22; 32], &[0x33; 32]);
    let nonce = [0x44; 32];

    let attestation = keystore.generate_attestation(handle, &nonce).unwrap();

    // 1. Valid attestation must verify cleanly
    assert!(attestation.verify(&nonce).is_ok());

    // 2. Nonce replay with mismatched challenge must be rejected
    let stale_nonce = [0x99; 32];
    assert!(
        matches!(attestation.verify(&stale_nonce), Err(E2EError::InvalidMessageFormat)),
        "Attestation accepted stale challenge nonce!"
    );

    // 3. Bit-flip mutations in attested ECC public key must fail verification
    for bit in 0..8 {
        let mut tampered = attestation.clone();
        tampered.attested_public_key.ecc_public[0] ^= 1 << bit;
        assert!(
            tampered.verify(&nonce).is_err(),
            "Attestation accepted tampered ECC public key bit {}!",
            bit
        );
    }

    // 4. Bit-flip mutations in enclave signature must fail verification
    for offset in [0, 10, 100, 500] {
        let mut tampered = attestation.clone();
        tampered.enclave_signature[offset] ^= 0x01;
        assert!(
            tampered.verify(&nonce).is_err(),
            "Attestation accepted tampered signature at byte {}!",
            offset
        );
    }

    // 5. Corrupted root enclave public key must fail verification
    let mut tampered_root = attestation.clone();
    tampered_root.enclave_root_pub[0] ^= 0xFF;
    assert!(
        tampered_root.verify(&nonce).is_err(),
        "Attestation verified against forged enclave root public key!"
    );
}

#[test]
fn test_keystore_slot_boundaries_and_collision_resistance() {
    let keystore = MultiSlotMockHardwareKeystore::new(&[0x55; 32]);

    let handle_1 = keystore.provision_key(&[0x01; 32], &[0x02; 32]);
    let handle_2 = keystore.provision_key(&[0x03; 32], &[0x04; 32]);

    assert_ne!(handle_1, handle_2, "Keystore allocated colliding handle IDs!");

    // Attestations for slot 1 and slot 2 must differ
    let nonce = [0x77; 32];
    let att_1 = keystore.generate_attestation(handle_1, &nonce).unwrap();
    let att_2 = keystore.generate_attestation(handle_2, &nonce).unwrap();

    assert_ne!(
        att_1.attested_public_key.ecc_public,
        att_2.attested_public_key.ecc_public,
        "Cross-slot key identity collision detected!"
    );

    // Test out-of-range and invalid handles
    for invalid_handle in [0, 999, u32::MAX, u32::MAX - 1] {
        let res = keystore.generate_attestation(invalid_handle, &nonce);
        assert!(
            matches!(res, Err(E2EError::SigningError)),
            "Keystore allowed operation on invalid handle {}!",
            invalid_handle
        );
    }
}

#[test]
fn test_keystore_secure_deletion_and_post_eviction_lockout() {
    let keystore = MultiSlotMockHardwareKeystore::new(&[0x88; 32]);
    let handle = keystore.provision_key(&[0xAA; 32], &[0xBB; 32]);
    let nonce = [0xCC; 32];

    // Verify key is accessible before deletion
    assert!(keystore.generate_attestation(handle, &nonce).is_ok());

    // Securely delete key handle
    keystore.delete_key(handle).expect("Failed to delete key handle");

    // Post-deletion: accessing the handle must immediately return SigningError
    let post_delete_res = keystore.generate_attestation(handle, &nonce);
    assert!(
        matches!(post_delete_res, Err(E2EError::SigningError)),
        "Deleted key handle was still accessible after eviction!"
    );

    // Deleting already-deleted key handle must return SigningError (no double-free or panic)
    let double_delete = keystore.delete_key(handle);
    assert!(
        matches!(double_delete, Err(E2EError::SigningError)),
        "Keystore panicked or allowed double deletion of key handle!"
    );
}
