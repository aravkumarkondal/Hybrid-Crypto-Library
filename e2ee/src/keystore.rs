use alloc::vec::Vec;
use crate::errors::E2EError;
use crate::identity::IdentityPublicKey;

/// A platform-agnostic interface for hardware-backed identity key storage.
/// 
/// # Security Model & Hardware Limitations
/// Current hardware (TPMs, Secure Enclaves, `WebCrypto`) natively supports ECDSA, RSA, and occasionally ECDH, 
/// but does not natively support Post-Quantum algorithms like ML-DSA-87. 
/// 
/// To support a strictly Hybrid architecture:
/// * **X25519 (ECDH)** may remain entirely hardware-resident, depending on the specific platform adapter's capabilities.
/// * **ML-DSA-87** uses hardware-protected sealed storage. When `sign_payload` is invoked, the ML-DSA private key 
///   is decrypted and brought into hardened RAM **temporarily** for the duration of the signature operation, 
///   before being immediately zeroized upon the closure of the signing frame.
pub trait SecureKeyStore: Send + Sync {
    /// Returns the public key associated with this identity.
    fn public_key(&self) -> Result<IdentityPublicKey, E2EError>;

    /// Signs the provided message payload using the private identity key (ML-DSA-87).
    /// **WARNING:** This operation temporarily pulls the ML-DSA private key into RAM.
    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError>;

    /// Computes the ECDH shared secret using the private identity key (X25519) and the peer's public key.
    fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use crate::identity::{IdentityKeyPair, SoftwareIdentityKeyPair};

    struct MockHardwareStore {
        sw_key: SoftwareIdentityKeyPair,
    }

    impl SecureKeyStore for MockHardwareStore {
        fn public_key(&self) -> Result<IdentityPublicKey, E2EError> {
            Ok(IdentityPublicKey {
                ecc_public: self.sw_key.ecc_public,
                pqc_public: self.sw_key.pqc_public.clone(),
            })
        }

        fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, E2EError> {
            hybrid_crypto::ml_dsa::ml_dsa_87_sign(&self.sw_key.pqc_private, data, &[], rnd)
                .map_err(|_| E2EError::SigningError)
        }

        fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32], E2EError> {
            hybrid_crypto::x25519::x25519(&self.sw_key.ecc_private, peer_public)
                .map_err(|_| E2EError::InvalidPreKeyBundle)
        }
    }

    #[test]
    fn test_secure_keystore_abstraction() {
        let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
        let mock_store = MockHardwareStore { sw_key };
        let hardware_id = IdentityKeyPair::from_hardware(Box::new(mock_store));

        let msg = b"test message for hardware store";
        let sig = hardware_id.sign(msg, &[9; 32]).unwrap();

        let pub_key = hardware_id.public_key();
        assert!(pub_key.verify(msg, &sig));

        // Test extraction prevention (ecc_private_bytes should fail)
        assert!(hardware_id.ecc_private_bytes().is_err());
    }
}
