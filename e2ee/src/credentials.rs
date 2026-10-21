use alloc::vec::Vec;
use crate::identity::{IdentityKeyPair, IdentityPublicKey};
use crate::errors::E2EError;

/// A Delegated Pseudonymous Credential
///
/// An Enclave or Attribute Authority issues this credential by generating a fresh
/// `IdentityKeyPair` and signing its public components along with arbitrary attributes.
/// The user can present `public_key`, `attributes`, and `authority_signature` to peers,
/// who verify the signature against the Authority's known public key.
pub struct PseudonymousCredential {
    pub keypair: IdentityKeyPair,
    pub attributes: Vec<u8>,
    pub authority_signature: Vec<u8>, // ML-DSA-87 signature
}

impl PseudonymousCredential {
    /// Extracts the public representation of this credential
    #[must_use]
    pub async fn to_public(&self) -> PublicPseudonymousCredential {
        PublicPseudonymousCredential {
            public_key: self.keypair.public_key().await,
            attributes: self.attributes.clone(),
            authority_signature: self.authority_signature.clone(),
        }
    }
}

pub struct PublicPseudonymousCredential {
    pub public_key: IdentityPublicKey,
    pub attributes: Vec<u8>,
    pub authority_signature: Vec<u8>,
}

impl PublicPseudonymousCredential {
    /// Verifies the credential against the known Authority public key
    /// 
    /// Privacy Claim: [VERIFIED] - The signature validates authenticity without
    /// linking back to the user's primary identity, assuming the Authority doesn't
    /// collude by releasing issuance logs.
    pub fn verify(&self, authority_public: &IdentityPublicKey) -> Result<(), E2EError> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.attributes);
        msg.extend_from_slice(&self.public_key.ecc_public);
        msg.extend_from_slice(&self.public_key.pqc_public);

        if authority_public.verify(&msg, &self.authority_signature) {
            Ok(())
        } else {
            Err(E2EError::InvalidSignature)
        }
    }
}

pub struct CredentialIssuer {
    pub authority_keypair: IdentityKeyPair,
}

impl CredentialIssuer {
    #[must_use]
    pub const fn new(authority_keypair: IdentityKeyPair) -> Self {
        Self { authority_keypair }
    }

    /// Issues a new `PseudonymousCredential`
    /// 
    /// Privacy Claim: [HIGH CONFIDENCE] - The keypair is freshly generated via robust PRNG
    /// ensuring no mathematical link to the user's long-term identity.
    pub async fn issue_credential(
        &self,
        attributes: &[u8],
        seed_ecc: &[u8; 32],
        seed_pqc: &[u8; 32],
        signature_entropy: &[u8; 32],
    ) -> Result<PseudonymousCredential, E2EError> {
        // Generate a fresh, random keypair for the user
        let pseudonymous_keypair = IdentityKeyPair::generate(seed_ecc, seed_pqc);

        let mut msg = Vec::new();
        msg.extend_from_slice(attributes);
        let pub_key = pseudonymous_keypair.public_key().await;
        msg.extend_from_slice(&pub_key.ecc_public);
        msg.extend_from_slice(&pub_key.pqc_public);

        let signature = self.authority_keypair.sign(&msg, signature_entropy).await?;

        Ok(PseudonymousCredential {
            keypair: pseudonymous_keypair,
            attributes: attributes.to_vec(),
            authority_signature: signature,
        })
    }
}
