extern crate alloc;
use e2ee::identity::{IdentityKeyPair, SoftwareIdentityKeyPair, IdentityPublicKey};
use e2ee::keystore::SecureKeyStore;
use e2ee::errors::E2EError;
use alloc::boxed::Box;
use alloc::vec::Vec;

struct MockCorruptibleKeystore {
    is_corrupted: bool,
    sw_key: SoftwareIdentityKeyPair,
}

impl SecureKeyStore for MockCorruptibleKeystore {
    fn public_key(&self) -> Result<IdentityPublicKey, E2EError> {
        Ok(IdentityPublicKey {
            ecc_public: self.sw_key.ecc_public,
            pqc_public: self.sw_key.pqc_public.clone(),
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError> {
        if self.is_corrupted {
            return Err(E2EError::SigningError);
        }
        hybrid_crypto::ml_dsa::ml_dsa_87_sign(&self.sw_key.pqc_private, data, &[], rnd)
            .map_err(|_| E2EError::SigningError)
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError> {
        if self.is_corrupted {
            return Err(E2EError::InvalidPreKeyBundle);
        }
        hybrid_crypto::x25519::x25519(&self.sw_key.ecc_private, peer_public)
            .map_err(|_| E2EError::InvalidPreKeyBundle)
    }
}

#[test]
fn test_extraction_resistance() {
    let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let store = MockCorruptibleKeystore { is_corrupted: false, sw_key };
    let hw_id = IdentityKeyPair::from_hardware(Box::new(store));

    // Attack simulation: Attempting to extract the X25519 private key from the hardware wrapper.
    let result = hw_id.ecc_private_bytes();
    
    assert!(result.is_err(), "Hardware wrapper must block raw extraction of X25519 private keys");
}

#[test]
fn test_storage_corruption() {
    let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let store = MockCorruptibleKeystore { is_corrupted: true, sw_key };
    let hw_id = IdentityKeyPair::from_hardware(Box::new(store));

    let msg = b"test message";
    let rnd = [9; 32];
    
    // Attack simulation: The backing keystore blob has been bit-flipped (corrupted).
    let sig_result = hw_id.sign(msg, &rnd);
    
    assert!(sig_result.is_err(), "Hardware must fail securely when backing blob is corrupted");
}

#[test]
fn test_type_level_downgrade_prevention() {
    let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
    let store = MockCorruptibleKeystore { is_corrupted: false, sw_key };
    let hw_id = IdentityKeyPair::from_hardware(Box::new(store));

    // Attack simulation: Attempting to cast or extract the inner Software struct from the Hardware variant.
    // In Rust, we can test this by matching the variant.
    match hw_id {
        IdentityKeyPair::Software(_) => panic!("Hardware variant was downgraded to Software"),
        IdentityKeyPair::Hardware(_) => { /* Expected, safe */ },
    }
}
