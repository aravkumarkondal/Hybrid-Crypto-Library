extern crate alloc;

use e2ee::keystore::{SecureKeyStore, BoxFuture};
use e2ee::identity::{IdentityKeyPair, IdentityPublicKey, SoftwareIdentityKeyPair};
use e2ee::errors::E2EError;
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HardwareFailureMode {
    Healthy,
    DeviceDisconnected,
    EntropyDepleted,
    PinLocked,
    TransientFault(usize), // Fails first N times, then recovers
}

struct ResilientMockHardwareKeystore {
    inner_key: SoftwareIdentityKeyPair,
    mode: Arc<Mutex<HardwareFailureMode>>,
    fault_counter: Arc<Mutex<usize>>,
}

impl ResilientMockHardwareKeystore {
    fn new(entropy_ecc: &[u8; 32], entropy_pqc: &[u8; 32], mode: HardwareFailureMode) -> Self {
        Self {
            inner_key: SoftwareIdentityKeyPair::generate(entropy_ecc, entropy_pqc),
            mode: Arc::new(Mutex::new(mode)),
            fault_counter: Arc::new(Mutex::new(0)),
        }
    }

    fn check_fault(&self) -> Result<(), E2EError> {
        let mode = *self.mode.lock().unwrap();
        match mode {
            HardwareFailureMode::Healthy => Ok(()),
            HardwareFailureMode::DeviceDisconnected => Err(E2EError::SigningError),
            HardwareFailureMode::EntropyDepleted => Err(E2EError::EncryptionError),
            HardwareFailureMode::PinLocked => Err(E2EError::InvalidSignature),
            HardwareFailureMode::TransientFault(n) => {
                let mut cnt = self.fault_counter.lock().unwrap();
                if *cnt < n {
                    *cnt += 1;
                    Err(E2EError::SigningError)
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl SecureKeyStore for ResilientMockHardwareKeystore {
    fn public_key(&self) -> BoxFuture<'_, Result<IdentityPublicKey, E2EError>> {
        let pk = IdentityPublicKey {
            ecc_public: self.inner_key.ecc_public,
            pqc_public: self.inner_key.pqc_public.clone(),
        };
        alloc::boxed::Box::pin(async move {
            self.check_fault()?;
            Ok(pk)
        })
    }

    fn sign_payload(&self, data: &[u8], rnd: &[u8; 32]) -> BoxFuture<'_, Result<alloc::vec::Vec<u8>, E2EError>> {
        let data = data.to_vec();
        let rnd = *rnd;
        let sk = self.inner_key.pqc_private.clone();
        alloc::boxed::Box::pin(async move {
            self.check_fault()?;
            hybrid_crypto::ml_dsa::ml_dsa_87_sign(&sk, &data, &[], &rnd)
                .map_err(|_| E2EError::SigningError)
        })
    }

    fn shared_secret(&self, peer_public: &[u8; 32]) -> BoxFuture<'_, Result<[u8; 32], E2EError>> {
        let peer_pub = *peer_public;
        let sk = self.inner_key.ecc_private;
        alloc::boxed::Box::pin(async move {
            self.check_fault()?;
            hybrid_crypto::x25519::x25519(&sk, &peer_pub)
                .map_err(|_| E2EError::InvalidPreKeyBundle)
        })
    }
}

#[test]
fn test_hardware_device_disconnection_mid_operation() {
    let mock = ResilientMockHardwareKeystore::new(&[1; 32], &[2; 32], HardwareFailureMode::DeviceDisconnected);
    let hw_id = IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock));

    // Calling public_key panics if hardware fails, which can be caught safely with catch_unwind
    let pub_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        futures::executor::block_on(hw_id.public_key())
    }));
    assert!(pub_res.is_err(), "Hardware failure during public_key() must be signaled");

    let sign_res = futures::executor::block_on(hw_id.sign(b"critical payload", &[0u8; 32]));
    assert!(sign_res.is_err(), "Hardware sign must fail gracefully on disconnection");

    let ss_res = futures::executor::block_on(hw_id.ecdh(&[9u8; 32]));
    assert!(ss_res.is_err(), "Hardware DH must fail gracefully on disconnection");
}

#[test]
fn test_hardware_transient_fault_and_retry_recovery() {
    // Fails the first 2 operations, then recovers
    let mock = ResilientMockHardwareKeystore::new(&[3; 32], &[4; 32], HardwareFailureMode::TransientFault(2));
    let hw_id = IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock));

    let payload = b"transient test";
    let rnd = [5u8; 32];

    // Attempt 1 -> fails
    assert!(futures::executor::block_on(hw_id.sign(payload, &rnd)).is_err());
    // Attempt 2 -> fails
    assert!(futures::executor::block_on(hw_id.sign(payload, &rnd)).is_err());
    // Attempt 3 -> succeeds!
    let sig = futures::executor::block_on(hw_id.sign(payload, &rnd)).expect("Hardware should recover after transient faults");
    assert!(!sig.is_empty());
}

#[test]
fn test_hardware_pin_lockout_rejection() {
    let mock = ResilientMockHardwareKeystore::new(&[7; 32], &[8; 32], HardwareFailureMode::PinLocked);
    let hw_id = IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock));

    let err = futures::executor::block_on(hw_id.sign(b"locked action", &[0u8; 32])).unwrap_err();
    assert_eq!(err, E2EError::InvalidSignature);
}

#[test]
fn test_hardware_entropy_depleted_failure() {
    let mock = ResilientMockHardwareKeystore::new(&[9; 32], &[10; 32], HardwareFailureMode::EntropyDepleted);
    let hw_id = IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock));

    let err = futures::executor::block_on(hw_id.sign(b"needs entropy", &[0u8; 32])).unwrap_err();
    assert_eq!(err, E2EError::EncryptionError);
}

#[test]
fn test_hardware_multithreaded_concurrency_stress() {
    // Verify that concurrent calls to hardware keystore from 8 threads do not corrupt state or deadlock
    let mock = ResilientMockHardwareKeystore::new(&[11; 32], &[12; 32], HardwareFailureMode::Healthy);
    let hw_id = Arc::new(IdentityKeyPair::Hardware(alloc::boxed::Box::new(mock)));

    let mut handles = Vec::new();
    for thread_id in 0..8 {
        let hw_clone = Arc::clone(&hw_id);
        handles.push(thread::spawn(move || {
            let valid_peer_pub = hybrid_crypto::x25519::x25519_base(&[thread_id as u8 + 1; 32]);
            for i in 0..20 {
                let msg = format!("Thread {} iter {}", thread_id, i);
                let rnd = [thread_id as u8 + 1; 32];
                let sig = futures::executor::block_on(hw_clone.sign(msg.as_bytes(), &rnd)).unwrap();
                assert!(!sig.is_empty());

                let ss = futures::executor::block_on(hw_clone.ecdh(&valid_peer_pub)).unwrap();
                assert_eq!(ss.len(), 32);
            }
        }));
    }

    for h in handles {
        h.join().expect("Hardware multithreaded test thread panicked!");
    }
}
