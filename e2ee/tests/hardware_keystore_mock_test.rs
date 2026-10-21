extern crate alloc;

use e2ee::keystore::SecureKeyStore;
use e2ee::identity::IdentityKeyPair;
use e2ee::errors::E2EError;

// Mock store to verify the trait bounds and expected behaviors of a keystore
#[allow(dead_code)]
struct MockKeyStore {
    ecc_public: [u8; 32],
    pqc_public: alloc::vec::Vec<u8>,
    ecc_private: [u8; 32],
    pqc_private: alloc::vec::Vec<u8>,
}

impl SecureKeyStore for MockKeyStore {
    fn public_key(&self) -> e2ee::keystore::BoxFuture<'_, Result<e2ee::identity::IdentityPublicKey, E2EError>> {
        let pub_key = e2ee::identity::IdentityPublicKey {
            ecc_public: self.ecc_public,
            pqc_public: self.pqc_public.clone(),
        };
        alloc::boxed::Box::pin(async move {
            Ok(pub_key)
        })
    }

    fn sign_payload(&self, _data: &[u8], _rnd: &[u8; 32]) -> e2ee::keystore::BoxFuture<'_, Result<alloc::vec::Vec<u8>, E2EError>> {
        alloc::boxed::Box::pin(async move {
            Err(E2EError::InvalidSignature)
        })
    }

    fn shared_secret(&self, _peer_public: &[u8; 32]) -> e2ee::keystore::BoxFuture<'_, Result<[u8; 32], E2EError>> {
        alloc::boxed::Box::pin(async move {
            Err(E2EError::InvalidPreKeyBundle)
        })
    }
}

#[test]
fn test_mock_hardware_keystore_trait_object() {
    let mock = MockKeyStore {
        ecc_public: [0u8; 32],
        pqc_public: alloc::vec![0u8; 1184],
        ecc_private: [0u8; 32],
        pqc_private: alloc::vec![0u8; 2592],
    };
    
    // Ensure it can be boxed into IdentityKeyPair::Hardware
    let identity = IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock));
    
    match identity {
        IdentityKeyPair::Hardware(store) => {
            let pub_key = futures::executor::block_on(store.public_key()).unwrap();
            assert_eq!(pub_key.ecc_public, [0u8; 32]);
            assert_eq!(pub_key.pqc_public.len(), 1184);
            
            // Try to sign, expecting the mock error
            let sig = store.sign_payload(b"test", &[0u8; 32]);
            assert!(matches!(futures::executor::block_on(sig), Err(E2EError::InvalidSignature)));
            
            // Try to compute shared secret, expecting mock error
            let ss = store.shared_secret(&[1u8; 32]);
            assert!(matches!(futures::executor::block_on(ss), Err(E2EError::InvalidPreKeyBundle)));
        },
        _ => panic!("Expected Hardware variant"),
    }
}
