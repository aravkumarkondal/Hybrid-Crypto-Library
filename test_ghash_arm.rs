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
unsafe fn gf128_mul_pmull(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    // Need to test how PMULL works.
    let _a_vec = vld1q_u8(a.as_ptr());
    let _b_vec = vld1q_u8(b.as_ptr());
    [0u8; 16]
}

fn main() {
    let a = [1u8; 16];
    let b = [2u8; 16];
    println!("Soft: {:?}", gf128_mul_soft(&a, &b));
}
