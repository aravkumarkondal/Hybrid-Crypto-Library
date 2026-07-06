use alloc::vec::Vec;
use crate::CryptoError;
use crate::ml_kem::{ml_kem_768_keypair, ml_kem_768_encapsulate, ml_kem_768_decapsulate};
#[cfg(feature = "ml-dsa")]
use crate::ml_dsa::{ml_dsa_87_keypair, ml_dsa_87_sign, ml_dsa_87_verify};
use crate::x25519::{x25519_base, x25519};

pub trait CryptoProvider {
    fn kem_generate_keypair(entropy: &[u8; 64]) -> ([u8; 1184], [u8; 2400]);
    fn kem_encapsulate(public_key: &[u8; 1184], entropy: &[u8; 32]) -> Result<([u8; 1088], [u8; 32]), CryptoError>;
    fn kem_decapsulate(private_key: &[u8; 2400], ciphertext: &[u8; 1088]) -> [u8; 32];
    
    fn x25519_generate_keypair(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]);
    fn x25519_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], CryptoError>;
}

pub struct StandardCryptoProvider;

impl CryptoProvider for StandardCryptoProvider {
    fn kem_generate_keypair(entropy: &[u8; 64]) -> ([u8; 1184], [u8; 2400]) {
        ml_kem_768_keypair(entropy)
    }
    
    fn kem_encapsulate(public_key: &[u8; 1184], entropy: &[u8; 32]) -> Result<([u8; 1088], [u8; 32]), CryptoError> {
        ml_kem_768_encapsulate(public_key, entropy)
    }
    
    fn kem_decapsulate(private_key: &[u8; 2400], ciphertext: &[u8; 1088]) -> [u8; 32] {
        ml_kem_768_decapsulate(private_key, ciphertext)
    }
    
    fn x25519_generate_keypair(entropy: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let pub_key = x25519_base(entropy);
        (pub_key, *entropy)
    }
    
    fn x25519_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        x25519(private_key, public_key)
    }
}
