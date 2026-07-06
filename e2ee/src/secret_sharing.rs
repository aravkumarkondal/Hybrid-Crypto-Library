use alloc::vec::Vec;
use crate::errors::E2EError;

/// Galois Field GF(2^8) arithmetic
/// Irreducible polynomial used: x^8 + x^4 + x^3 + x + 1 (AES standard)
const GF256_POLY: u16 = 0x11b;

#[inline]
const fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set {
            a ^= (GF256_POLY & 0xFF) as u8;
        }
        b >>= 1;
    }
    p
}

fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // Invalid
    }
    // Fermat's Little Theorem in GF(256): a^(255) = 1, so a^(-1) = a^(254)
    let mut res = 1;
    let mut base = a;
    let mut exp = 254;
    while exp > 0 {
        if exp & 1 != 0 {
            res = gf_mul(res, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    res
}

fn gf_div(a: u8, b: u8) -> u8 {
    gf_mul(a, gf_inv(b))
}

fn evaluate_polynomial(x: u8, coeffs: &[u8]) -> u8 {
    let mut result = 0;
    // Horner's method
    for &coeff in coeffs.iter().rev() {
        result = gf_add(gf_mul(result, x), coeff);
    }
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretShare {
    pub x: u8,
    pub y: Vec<u8>,
}

pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Splits a secret into `n` shares, requiring `m` shares to reconstruct.
    /// 
    /// Note: `random_coefficients` must provide (m - 1) bytes of entropy for *each* byte 
    /// of the secret. Length of `random_coefficients` must be `secret.len() * (m - 1)`.
    pub fn split_secret(
        secret: &[u8],
        n: u8,
        m: u8,
        random_coefficients: &[u8],
    ) -> Result<Vec<SecretShare>, E2EError> {
        if m == 0 || n == 0 || m > n {
            return Err(E2EError::InvalidMessageFormat);
        }
        if random_coefficients.len() != secret.len() * (m as usize - 1) {
            return Err(E2EError::InvalidMessageFormat);
        }

        let mut shares = Vec::with_capacity(n as usize);
        for i in 1..=n {
            let mut y = alloc::vec![0u8; secret.len()];
            for (byte_idx, &secret_byte) in secret.iter().enumerate() {
                // Build polynomial for this specific byte
                let mut coeffs = alloc::vec![secret_byte];
                let offset = byte_idx * (m as usize - 1);
                coeffs.extend_from_slice(&random_coefficients[offset..offset + (m as usize - 1)]);
                
                y[byte_idx] = evaluate_polynomial(i, &coeffs);
            }
            shares.push(SecretShare { x: i, y });
        }
        
        Ok(shares)
    }

    /// Reconstructs the secret from `m` shares using Lagrange interpolation.
    pub fn reconstruct_secret(
        shares: &[SecretShare],
        m: u8,
    ) -> Result<Vec<u8>, E2EError> {
        if shares.len() < m as usize {
            return Err(E2EError::InvalidMessageFormat); // Not enough shares
        }
        // Validate all shares have same length
        let secret_len = shares[0].y.len();
        for share in shares {
            if share.y.len() != secret_len {
                return Err(E2EError::InvalidMessageFormat);
            }
        }

        let mut secret = alloc::vec![0u8; secret_len];
        
        // Lagrange interpolation at x = 0
        for byte_idx in 0..secret_len {
            let mut secret_byte = 0;
            
            for i in 0..(m as usize) {
                let share_i = &shares[i];
                let x_i = share_i.x;
                let y_i = share_i.y[byte_idx];
                
                let mut num = 1;
                let mut den = 1;
                
                for j in 0..(m as usize) {
                    if i != j {
                        let x_j = shares[j].x;
                        if x_i == x_j {
                            return Err(E2EError::InvalidMessageFormat); // Duplicate shares
                        }
                        num = gf_mul(num, gf_add(0, x_j)); // 0 - x_j
                        den = gf_mul(den, gf_add(x_i, x_j)); // x_i - x_j
                    }
                }
                
                let basis = gf_div(num, den);
                let term = gf_mul(y_i, basis);
                secret_byte = gf_add(secret_byte, term);
            }
            secret[byte_idx] = secret_byte;
        }

        Ok(secret)
    }
}
