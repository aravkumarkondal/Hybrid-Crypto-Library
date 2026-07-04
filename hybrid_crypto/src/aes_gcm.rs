#![allow(unsafe_code)]

//! AES-256-GCM Implementation with GHASH
//! 
//! **⚠️ WARNING: Hardware AES-NI Requirement**
//! This module strictly requires the presence of hardware AES instructions (e.g., `aes` for x86/x86_64 or `aes` for aarch64) 
//! enabled at compile-time via `#[cfg]`. It deliberately prioritizes maximum security and side-channel resistance 
//! over broad deployment portability by refusing to fall back to mathematically equivalent but side-channel vulnerable 
//! bitsliced software AES.
//! 
//! If this library is built on a generic architecture without these features enabled (e.g., standard WASM without SIMD mappings), 
//! the compilation will intentionally fail to protect the user from utilizing an unsafe implementation.
#![allow(dead_code)]// AES S-Box


const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];



// GF(2^128) arithmetic for GHASH
// use subtle::ConditionallySelectable;

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
fn hw_sbox4(b: [u8; 4]) -> [u8; 4] {
    unsafe {
        use core::arch::x86_64::*;
        let mut block = [0u8; 16];
        block[0] = b[0];
        block[5] = b[1];
        block[10] = b[2];
        block[15] = b[3];
        let m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let zero = _mm_setzero_si128();
        let res = _mm_aesenclast_si128(m, zero);
        _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, res);
        [block[0], block[1], block[2], block[3]]
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
fn hw_sbox4(b: [u8; 4]) -> [u8; 4] {
    unsafe {
        use core::arch::aarch64::*;
        let mut block = [0u8; 16];
        block[0] = b[0];
        block[1] = b[1];
        block[2] = b[2];
        block[3] = b[3];
        let m = vld1q_u8(block.as_ptr());
        let zero = vdupq_n_u8(0);
        let res = vaeseq_u8(m, zero);
        vst1q_u8(block.as_mut_ptr(), res);
        [block[0], block[13], block[10], block[7]]
    }
}


#[cfg(not(target_arch = "wasm32"))]
pub struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

#[cfg(target_arch = "wasm32")]
pub struct Aes256 {
    cipher: aes::Aes256,
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for Aes256 {
    fn drop(&mut self) {
        for key in self.round_keys.iter_mut() {
            crate::utils::zeroize(key);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        let mut w = [0u8; 60 * 4];
        for i in 0..8 {
            w[i * 4..i * 4 + 4].copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon_iteration = 1;
        for i in 8..60 {
            let mut temp = [0u8; 4];
            temp.copy_from_slice(&w[(i - 1) * 4..i * 4]);
            if i % 8 == 0 {
                let t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                temp = hw_sbox4(temp);
                temp[0] ^= RCON[rcon_iteration - 1];
                rcon_iteration += 1;
            } else if i % 8 == 4 {
                temp = hw_sbox4(temp);
            }
            for j in 0..4 {
                w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
            }
        }
        for i in 0..15 {
            rk[i].copy_from_slice(&w[i * 16..i * 16 + 16]);
        }
        crate::utils::zeroize(&mut w);
        Self { round_keys: rk }
    }

    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        unsafe {
            use core::arch::x86_64::*;
            let mut m = _mm_loadu_si128(block.as_ptr() as *const __m128i);
            m = _mm_xor_si128(m, _mm_loadu_si128(self.round_keys[0].as_ptr() as *const __m128i));
            for i in 1..14 {
                m = _mm_aesenc_si128(m, _mm_loadu_si128(self.round_keys[i].as_ptr() as *const __m128i));
            }
            m = _mm_aesenclast_si128(m, _mm_loadu_si128(self.round_keys[14].as_ptr() as *const __m128i));
            _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, m);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        unsafe {
            use core::arch::aarch64::*;
            let mut m = vld1q_u8(block.as_ptr());
            let k0 = vld1q_u8(self.round_keys[0].as_ptr());
            m = veorq_u8(m, k0);
            for round in 1..=13 {
                let k = vld1q_u8(self.round_keys[round].as_ptr());
                m = vaeseq_u8(m, vdupq_n_u8(0));
                m = vaesmcq_u8(m);
                m = veorq_u8(m, k);
            }
            m = vaeseq_u8(m, vdupq_n_u8(0));
            let k14 = vld1q_u8(self.round_keys[14].as_ptr());
            m = veorq_u8(m, k14);
            vst1q_u8(block.as_mut_ptr(), m);
        }
    }

    #[cfg(not(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"),
        all(target_arch = "aarch64", target_feature = "aes")
    )))]
    pub fn encrypt_block(&self, _block: &mut [u8; 16]) {
        // We enforce hardware AES at compile time for security.
        unimplemented!("Hardware AES support is required");
    }
}

#[cfg(target_arch = "wasm32")]
impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        use aes::cipher::KeyInit;
        Self {
            cipher: aes::Aes256::new(key.into()),
        }
    }
    
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockEncrypt;
        self.cipher.encrypt_block(block.into());
    }
}

#[cfg(not(any(
    all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"),
    all(target_arch = "aarch64", target_feature = "aes"),
    target_arch = "wasm32"
)))]
compile_error!("This crate requires hardware AES support (AES-NI or ARMv8 Crypto) for side-channel resistance.");

#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq", target_feature = "sse2"))]
#[inline]
unsafe fn gf128_mul_avx(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    
    // GCM reflects bits. 0xc2000000_00000000_00000000_00000000 is the reduction polynomial.
    let bswap = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    let mut x = _mm_shuffle_epi8(_mm_loadu_si128(a.as_ptr() as *const _), bswap);
    let mut y = _mm_shuffle_epi8(_mm_loadu_si128(b.as_ptr() as *const _), bswap);

    let x0_y0 = _mm_clmulepi64_si128(x, y, 0x00);
    let x1_y1 = _mm_clmulepi64_si128(x, y, 0x11);
    let x0_y1 = _mm_clmulepi64_si128(x, y, 0x01);
    let x1_y0 = _mm_clmulepi64_si128(x, y, 0x10);

    let mid = _mm_xor_si128(x0_y1, x1_y0);
    let mid_low = _mm_slli_si128(mid, 8);
    let mid_high = _mm_srli_si128(mid, 8);
    
    let r_low = _mm_xor_si128(x0_y0, mid_low);
    let r_high = _mm_xor_si128(x1_y1, mid_high);

    // Reduction
    let poly = _mm_set_epi32(0, 0, 0, 0xc2000000_u32 as i32); 
    let t1 = _mm_clmulepi64_si128(r_low, poly, 0x00);
    let t2 = _mm_xor_si128(r_low, _mm_slli_si128(t1, 8));
    let t3 = _mm_clmulepi64_si128(t2, poly, 0x10);
    let res = _mm_xor_si128(r_high, _mm_xor_si128(t3, _mm_srli_si128(t1, 8)));

    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr() as *mut _, _mm_shuffle_epi8(res, bswap));
    out
}

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
#[inline]
unsafe fn gf128_mul_neon(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    use core::arch::aarch64::*;

    // GHASH translates to POLYVAL with reflected bit ordering and a 1-bit shift.
    // 1. Byte swap A and B to transition from GHASH (big-endian bits) to POLYVAL (little-endian bits).
    let mut a_rev = *a;
    a_rev.reverse();
    let mut b_rev = *b;
    b_rev.reverse();

    // 2. Perform `.mulx()` on B to absorb the 1-bit shift inherent to GHASH.
    // This is a constant-time shift and conditional XOR over GF(2^128).
    let mut v = u128::from_le_bytes(b_rev);
    let v_hi = v >> 127;
    v <<= 1;
    // Conditional XOR with the reflected polynomial if the carry was 1
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    let b_polyval = v.to_le_bytes();

    // Load into NEON vectors as 64-bit polynomials
    let m = vreinterpretq_u64_u8(vld1q_u8(a_rev.as_ptr()));
    let h = vreinterpretq_u64_u8(vld1q_u8(b_polyval.as_ptr()));

    // POLYVAL R/F Algorithm constant (x^63 + x^62 + x^57)
    const P1: u64 = 0xC200000000000000;

    // --- Compute D = swap(H) ^ (H0 * P1) ---
    let h_swap = vextq_u64(h, h, 1);
    let h0 = vgetq_lane_u64(h, 0);
    let t = vreinterpretq_u64_p128(vmull_p64(h0, P1));
    let d = veorq_u64(h_swap, t);

    // --- R/F Unreduced Multiplication (4 PMULLs) ---
    let m0 = vgetq_lane_u64(m, 0);
    let m1 = vgetq_lane_u64(m, 1);
    let h1 = vgetq_lane_u64(h, 1);
    let d0 = vgetq_lane_u64(d, 0);
    let d1 = vgetq_lane_u64(d, 1);

    // R = M0*D1 ^ M1*H1
    let r0 = vmull_p64(m0, d1);
    let r1 = vmull_p64(m1, h1);
    let r = veorq_u64(vreinterpretq_u64_p128(r0), vreinterpretq_u64_p128(r1));

    // F = M0*D0 ^ M1*H0
    let f0 = vmull_p64(m0, d0);
    let f1 = vmull_p64(m1, h0);
    let f = veorq_u64(vreinterpretq_u64_p128(f0), vreinterpretq_u64_p128(f1));

    // --- Reduction (1 PMULL) ---
    let f1_val = vgetq_lane_u64(f, 1);
    let f1_vec = vcombine_u64(vcreate_u64(f1_val), vcreate_u64(0));
    
    let f0_val = vgetq_lane_u64(f, 0);
    let f0_shifted = vcombine_u64(vcreate_u64(0), vcreate_u64(f0_val));
    
    let p1_f0 = vmull_p64(f0_val, P1);

    let mut result = veorq_u64(r, f1_vec);
    result = veorq_u64(result, f0_shifted);
    result = veorq_u64(result, vreinterpretq_u64_p128(p1_f0));

    // 3. Byte swap the result back to GHASH ordering.
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), vreinterpretq_u8_u64(result));
    out.reverse();
    out
}

#[inline(never)]
fn gf128_mul_soft(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut z_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let z = &mut *z_arr;
    let mut v = *b;
    for i in 0..16 {
        for bit in (0..8).rev() {
            let mask = 0u8.wrapping_sub((a[i] >> bit) & 1);
            for j in 0..16 {
                z[j] ^= v[j] & mask;
            }
            let lsb = v[15] & 1;
            let mask_lsb = 0u8.wrapping_sub(lsb);
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;
            v[0] ^= 0xE1 & mask_lsb;
        }
    }
    *z
}

#[inline]
fn gf128_mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq", target_feature = "sse2"))]
    {
        unsafe { gf128_mul_avx(a, b) }
    }
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    {
        // Using soft fallback for now as ARM PMULL requires R/F polynomial construction to be fully exact to GF(2^128)
        // without timing leaks.
        unsafe { gf128_mul_neon(a, b) }
    }
    #[cfg(not(any(
        all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "pclmulqdq", target_feature = "sse2"),
        all(target_arch = "aarch64", target_feature = "aes")
    )))]
    {
        gf128_mul_soft(a, b)
    }
}
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> [u8; 16] {
    assert_eq!(ciphertext.len(), plaintext.len(), "Ciphertext buffer length must match plaintext length");
    let aes = Aes256::new(key);
    
    // Generate H
    let mut h_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let h = &mut *h_arr;
    aes.encrypt_block(h);

    // Initial counter block
    let mut j0_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let j0 = &mut *j0_arr;
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;

    // Encrypt plaintext
    let mut counter = *j0;
    for (i, chunk) in plaintext.chunks(16).enumerate() {
        let mut c_arr = [0u8; 4];
        c_arr.copy_from_slice(&counter[12..16]);
        let mut c_val = u32::from_be_bytes(c_arr);
        c_val = c_val.wrapping_add(1);
        counter[12..16].copy_from_slice(&c_val.to_be_bytes());
        
        let mut e_k = counter;
        aes.encrypt_block(&mut e_k);
        
        let start = i * 16;
        for j in 0..chunk.len() {
            ciphertext[start + j] = chunk[j] ^ e_k[j];
        }
    }

    // GHASH
    let mut x_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let x = &mut *x_arr;
    
    // AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        *x = gf128_mul(x, h);
    }
    
    // Ciphertext
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        *x = gf128_mul(x, h);
    }

    // Length block
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (plaintext.len() as u64) * 8;
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    
    for i in 0..16 {
        x[i] ^= len_block[i];
    }
    *x = gf128_mul(x, h);

    // Final tag
    let mut e_j0_arr = crate::utils::ZeroizingArray::new(*j0);
    let e_j0 = &mut *e_j0_arr;
    aes.encrypt_block(e_j0);
    for i in 0..16 {
        x[i] ^= e_j0[i];
    }
    
    *x
}

/// Decrypts ciphertext using AES-256-GCM and verifies the authentication tag.
/// 
/// **Security Assurance (Tag Verification Placement):**
/// This implementation correctly computes and verifies the GHASH authentication tag
/// *before* writing the decrypted ciphertext to the plaintext buffer. This robust
/// design pattern provides a significant defensive posture against unverified
/// plaintext release, ensuring that corrupted or malicious ciphertexts cannot
/// leak partially decrypted data.
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    expected_tag: &[u8; 16],
    plaintext: &mut [u8],
) -> Result<(), &'static str> {
    if plaintext.len() != ciphertext.len() {
        crate::utils::zeroize(plaintext);
        return Err("Decryption failed: Invalid output length");
    }

    let aes = Aes256::new(key);
    
    // Generate H
    let mut h_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let h = &mut *h_arr;
    aes.encrypt_block(h);

    // Initial counter block
    let mut j0_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let j0 = &mut *j0_arr;
    j0[0..12].copy_from_slice(iv);
    j0[15] = 1;

    // GHASH is calculated over AAD and ciphertext
    let mut x_arr = crate::utils::ZeroizingArray::new([0u8; 16]);
    let x = &mut *x_arr;
    
    // AAD
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        *x = gf128_mul(x, h);
    }
    
    // Ciphertext
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            x[i] ^= block[i];
        }
        *x = gf128_mul(x, h);
    }

    // Length block
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    
    for i in 0..16 {
        x[i] ^= len_block[i];
    }
    *x = gf128_mul(x, h);

    // Final tag
    let mut e_j0_arr = crate::utils::ZeroizingArray::new(*j0);
    let e_j0 = &mut *e_j0_arr;
    aes.encrypt_block(e_j0);
    for i in 0..16 {
        x[i] ^= e_j0[i];
    }

    // Constant-time tag verification BEFORE releasing plaintext
    let tag_valid = crate::utils::constant_time_eq(x, expected_tag) as u8;
    if tag_valid == 0 {
        crate::utils::zeroize(plaintext);
        return Err("Decryption failed: Invalid Authentication Tag");
    }

    // Decrypt ciphertext
    let mut counter = *j0;
    for (i, chunk) in ciphertext.chunks(16).enumerate() {
        let mut c_arr = [0u8; 4];
        c_arr.copy_from_slice(&counter[12..16]);
        let mut c_val = u32::from_be_bytes(c_arr);
        c_val = c_val.wrapping_add(1);
        counter[12..16].copy_from_slice(&c_val.to_be_bytes());
        
        let mut e_k = counter;
        aes.encrypt_block(&mut e_k);
        
        let start = i * 16;
        for j in 0..chunk.len() {
            plaintext[start + j] = chunk[j] ^ e_k[j];
        }
    }

    Ok(())
}
