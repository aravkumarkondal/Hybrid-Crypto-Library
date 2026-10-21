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
use core::future::Future;
use core::pin::Pin;
use alloc::boxed::Box;

#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub trait SecureKeyStore {
    fn public_key(&self) -> BoxFuture<'_, Result<IdentityPublicKey, E2EError>>;
    fn sign_payload<'a>(&'a self, data: &'a [u8], rnd: &'a [u8; 32]) -> BoxFuture<'a, Result<Vec<u8>, E2EError>>;
    fn shared_secret<'a>(&'a self, peer_public: &'a [u8; 32]) -> BoxFuture<'a, Result<[u8; 32], E2EError>>;
}

#[cfg(not(target_arch = "wasm32"))]
pub trait SecureKeyStore: Send + Sync {
    fn public_key(&self) -> BoxFuture<'_, Result<IdentityPublicKey, E2EError>>;
    fn sign_payload<'a>(&'a self, data: &'a [u8], rnd: &'a [u8; 32]) -> BoxFuture<'a, Result<Vec<u8>, E2EError>>;
    fn shared_secret<'a>(&'a self, peer_public: &'a [u8; 32]) -> BoxFuture<'a, Result<[u8; 32], E2EError>>;
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
        fn public_key(&self) -> BoxFuture<'_, Result<IdentityPublicKey, E2EError>> {
            Box::pin(async {
                Ok(IdentityPublicKey {
                    ecc_public: self.sw_key.ecc_public,
                    pqc_public: self.sw_key.pqc_public.clone(),
                })
            })
        }

        fn sign_payload<'a>(&'a self, data: &'a [u8], rnd: &'a [u8; 32]) -> BoxFuture<'a, Result<Vec<u8>, E2EError>> {
            Box::pin(async {
                hybrid_crypto::ml_dsa::ml_dsa_87_sign(&self.sw_key.pqc_private, data, &[], rnd)
                    .map_err(|_| E2EError::SigningError)
            })
        }

        fn shared_secret<'a>(&'a self, peer_public: &'a [u8; 32]) -> BoxFuture<'a, Result<[u8; 32], E2EError>> {
            Box::pin(async {
                hybrid_crypto::x25519::x25519(&self.sw_key.ecc_private, peer_public)
                    .map_err(|_| E2EError::InvalidPreKeyBundle)
            })
        }
    }

    #[test]
    fn test_hardware_mock_integration() {
        use crate::ffi::block_on;
        let mut ecc_entropy = [0u8; 32];
        let mut pqc_entropy = [0u8; 32];
        ecc_entropy[0] = 5;
        pqc_entropy[0] = 6;
        
        let sw_key = SoftwareIdentityKeyPair::generate(&ecc_entropy, &pqc_entropy);
        let mock = MockHardwareStore { sw_key };
        let hardware_id = IdentityKeyPair::from_hardware(Box::new(mock));
        
        let msg = b"Testing Hardware Integration";
        let sig = block_on(hardware_id.sign(msg, &[9; 32])).unwrap();
        
        let pub_key = block_on(hardware_id.public_key());
        assert!(pub_key.verify(msg, &sig));
    }

    #[test]
    fn test_secure_keystore_abstraction() {
        use crate::ffi::block_on;
        let sw_key = SoftwareIdentityKeyPair::generate(&[1; 32], &[2; 32]);
        let mock_store = MockHardwareStore { sw_key };
        let hardware_id = IdentityKeyPair::from_hardware(Box::new(mock_store));

        let msg = b"test message for hardware store";
        let sig = block_on(hardware_id.sign(msg, &[9; 32])).unwrap();

        let pub_key = block_on(hardware_id.public_key());
        assert!(pub_key.verify(msg, &sig));

        // Test extraction prevention (ecc_private_bytes should fail)
        assert!(hardware_id.ecc_private_bytes().is_err());
    }
}
