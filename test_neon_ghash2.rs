use std::arch::aarch64::*;

fn gf128_mul_soft(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *b;
    for i in 0..16 {
        for bit in (0..8).rev() {
            let mask = 0u8.wrapping_sub((a[i] >> bit) & 1);
            for j in 0..16 { z[j] ^= v[j] & mask; }
            let lsb = v[15] & 1;
            for j in (1..16).rev() { v[j] = (v[j] >> 1) | (v[j - 1] << 7); }
            v[0] >>= 1;
            v[0] ^= 0xE1 & (0u8.wrapping_sub(lsb));
        }
    }
    z
}

#[target_feature(enable = "aes")]
unsafe fn gf128_mul_neon(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // GHASH using PMULL
    let va = vld1q_u8(a.as_ptr());
    let vb = vld1q_u8(b.as_ptr());

    // We must bit-reverse the bytes to match GCM bit reflection if we use standard polynomial.
    // However, ARM has pmull instruction which works on polynomials.
    // The GCM polynomial is x^128 + x^7 + x^2 + x + 1.
    // When bit-reflected, we use 0xE1.
    
    // Instead of full PMULL, let's just use the widely known 4-bit table approach.
    // Wait, I will try to implement PMULL.
    
    // Reverse bytes of inputs.
    let rev8_mask = vcombine_u8(
        vcreate_u8(0x0001020304050607), 
        vcreate_u8(0x08090a0b0c0d0e0f)
    );
    // Actually, AArch64 vrev64q_u8 reverses bytes in 64-bit halves.
    // Then vextq_u8 swaps the 64-bit halves.
    
    let a_rev = vextq_u8(vrev64q_u8(va), vrev64q_u8(va), 8);
    let b_rev = vextq_u8(vrev64q_u8(vb), vrev64q_u8(vb), 8);
    
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), va);
    out
}

fn main() {
    let a = [1u8; 16];
    let b = [2u8; 16];
    unsafe { gf128_mul_neon(&a, &b); }
}
