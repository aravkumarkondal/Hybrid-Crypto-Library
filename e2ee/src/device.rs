use alloc::vec::Vec;
use crate::identity::{IdentityKeyPair, IdentityPublicKey};
use crate::errors::E2EError;
use hybrid_crypto::utils::constant_time_eq;

/// Represents an Account Identity, which holds the root ML-DSA-87 and X25519 keys.
/// It is responsible for signing and revoking Device Identities.
pub struct AccountIdentity {
    pub root_key: IdentityKeyPair,
}

impl AccountIdentity {
    #[must_use]
    pub const fn new(root_key: IdentityKeyPair) -> Self {
        Self { root_key }
    }

    /// Signs a given Device's public key, certifying it belongs to this account.
    pub fn certify_device(&self, device_pub: &IdentityPublicKey, rnd: &[u8; 32]) -> Result<DeviceSignature, E2EError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DEVICE_CERTIFICATION");
        payload.extend_from_slice(&device_pub.ecc_public);
        payload.extend_from_slice(&device_pub.pqc_public);
        
        let signature = self.root_key.sign(&payload, rnd)?;
        Ok(DeviceSignature(signature))
    }
}

/// A signature produced by the Account Identity over a Device's Public Key.
#[derive(Clone, Debug)]
pub struct DeviceSignature(pub Vec<u8>);

/// Represents a physical or logical device's identity keypair.
pub struct DeviceKeyPair {
    pub device_id: u32,
    pub keypair: IdentityKeyPair,
}

impl DeviceKeyPair {
    #[must_use]
    pub const fn new(device_id: u32, keypair: IdentityKeyPair) -> Self {
        Self { device_id, keypair }
    }
    
    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        self.keypair.public_key()
    }
}

/// Information necessary to verify a device's association with an account.
#[derive(Clone, Debug)]
pub struct DeviceRegistration {
    pub device_id: u32,
    pub device_pub: IdentityPublicKey,
    pub signature: DeviceSignature,
}

impl DeviceRegistration {
    #[must_use]
    pub fn verify(&self, account_pub: &IdentityPublicKey) -> bool {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DEVICE_CERTIFICATION");
        payload.extend_from_slice(&self.device_pub.ecc_public);
        payload.extend_from_slice(&self.device_pub.pqc_public);
        
        account_pub.verify(&payload, &self.signature.0)
    }
}

/// A monotonic list of active devices for an account.
/// Prevent rollback attacks via versioning and timestamps.
#[derive(Clone, Debug)]
pub struct DeviceList {
    pub account_pub: IdentityPublicKey,
    pub version: u64,
    pub timestamp: u64,
    pub active_devices: Vec<DeviceRegistration>,
    pub signature: Vec<u8>,
}

impl DeviceList {
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"DEVICE_LIST");
        payload.extend_from_slice(&self.version.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        
        for dev in &self.active_devices {
            payload.extend_from_slice(&dev.device_id.to_le_bytes());
            payload.extend_from_slice(&dev.device_pub.ecc_public);
            payload.extend_from_slice(&dev.device_pub.pqc_public);
            payload.extend_from_slice(&dev.signature.0);
        }
        
        self.account_pub.verify(&payload, &self.signature)
    }

    /// Verifies this list against an older cached list to prevent rollback attacks.
    #[must_use]
    pub fn is_valid_update_from(&self, cached: &Self) -> bool {
        if !constant_time_eq(&self.account_pub.ecc_public, &cached.account_pub.ecc_public) {
            return false;
        }
        if self.version <= cached.version {
            return false; // Strict monotonicity required
        }
        if self.timestamp <= cached.timestamp {
            return false;
        }
        self.verify()
    }
}
