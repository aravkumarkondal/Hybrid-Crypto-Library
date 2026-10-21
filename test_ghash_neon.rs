use std::arch::aarch64::*;

fn gf128_mul_soft(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
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
    z
}

#[target_feature(enable = "aes")]
unsafe fn gf128_mul_neon(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // We want to match soft implementation.
    // The soft implementation processes MSB first. This is standard GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1
    // where bytes are big-endian and bits within byte are big-endian. (This is actually the GCM representation!).
    
    // Reverse bytes so that byte 0 becomes the most significant part
    let bswap = vcombine_u8(vcreate_u8(0x08090a0b0c0d0e0f), vcreate_u8(0x0001020304050607));
    
    // Actually, PMULL treats 64-bit lanes as polynomials.
    // AArch64 vmull_p64 expects poly64_t.
    // Let's just do a naive PMULL and see the result.
    let x = vld1q_u8(a.as_ptr());
    let y = vld1q_u8(b.as_ptr());
    
    let x_rev = vqtbl1q_u8(x, bswap);
    let y_rev = vqtbl1q_u8(y, bswap);
    
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), x_rev);
    out
}

fn main() {
    let mut a = [0u8; 16];
    a[0] = 0x80; // highest bit
    let mut b = [0u8; 16];
    b[15] = 0x01; // lowest bit
    println!("Soft: {:?}", gf128_mul_soft(&a, &b));
}
