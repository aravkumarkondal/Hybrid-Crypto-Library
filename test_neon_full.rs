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
    let rev_mask = vcombine_u8(vcreate_u8(0x0001020304050607), vcreate_u8(0x08090a0b0c0d0e0f));
    let va = vqtbl1q_u8(vld1q_u8(a.as_ptr()), rev_mask);
    let vb = vqtbl1q_u8(vld1q_u8(b.as_ptr()), rev_mask);

    let a64 = vreinterpretq_p64_u8(va);
    let b64 = vreinterpretq_p64_u8(vb);

    // Multiply
    let z_high = vmull_high_p64(a64, b64);
    let z_low = vmull_p64(vgetq_lane_p64(a64, 0), vgetq_lane_p64(b64, 0));
    let mid_a = vextq_p64(a64, a64, 1);
    let mid_b = vextq_p64(b64, b64, 1);
    let a_mid = veorq_p64(a64, mid_a);
    let b_mid = veorq_p64(b64, mid_b);
    let z_mid = vmull_p64(vgetq_lane_p64(a_mid, 0), vgetq_lane_p64(b_mid, 0));
    
    // Combine
    let mid = veorq_p64(veorq_p64(z_mid, z_high), z_low);
    // ...
    // Let me just test if I can compile this.
    [0u8; 16]
}

fn main() {
}
