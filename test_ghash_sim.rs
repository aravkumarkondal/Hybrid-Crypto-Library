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

unsafe fn clmul(a: uint8x16_t, b: uint8x16_t, imm: u8) -> uint8x16_t {
    let a64 = vreinterpretq_p64_u8(a);
    let b64 = vreinterpretq_p64_u8(b);
    let aa = if imm & 0x01 != 0 { vgetq_lane_p64(a64, 1) } else { vgetq_lane_p64(a64, 0) };
    let bb = if imm & 0x10 != 0 { vgetq_lane_p64(b64, 1) } else { vgetq_lane_p64(b64, 0) };
    vreinterpretq_u8_p128(vmull_p64(aa, bb))
}

#[target_feature(enable = "aes")]
unsafe fn gf128_mul_sim(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let bswap = vcombine_u8(vcreate_u8(0x0001020304050607), vcreate_u8(0x08090a0b0c0d0e0f));
    let x = vqtbl1q_u8(vld1q_u8(a.as_ptr()), bswap);
    let y = vqtbl1q_u8(vld1q_u8(b.as_ptr()), bswap);

    let x0_y0 = clmul(x, y, 0x00);
    let x1_y1 = clmul(x, y, 0x11);
    let x0_y1 = clmul(x, y, 0x01);
    let x1_y0 = clmul(x, y, 0x10);

    let mid = veorq_u8(x0_y1, x1_y0);
    let mid_low = vextq_u8(vdupq_n_u8(0), mid, 8); // slli_si128(mid, 8)
    let mid_high = vextq_u8(mid, vdupq_n_u8(0), 8); // srli_si128(mid, 8)
    
    let r_low = veorq_u8(x0_y0, mid_low);
    let r_high = veorq_u8(x1_y1, mid_high);

    // poly = 0xc2000000_00000000_00000000_00000000
    // In little endian bytes, this is [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc2] ?
    // No, 0xc2 is the MSB of the low 64-bit word!
    // low 64-bit word = 0xc2000000_00000000. MSB is at byte 7.
    let mut poly_bytes = [0u8; 16];
    poly_bytes[7] = 0xc2;
    let poly = vld1q_u8(poly_bytes.as_ptr());

    let t1 = clmul(r_low, poly, 0x00);
    let t2 = veorq_u8(r_low, vextq_u8(vdupq_n_u8(0), t1, 8)); // slli_si128(t1, 8)
    let t3 = clmul(t2, poly, 0x10); // Wait, poly high 64-bits is 0! So 0x10 means poly high 64-bits (0) * t2 low 64-bits. That's 0!
    // Wait, Intel says: pclmulqdq xmm2, xmm3, 0x10.
    // That means: t2 high 64-bits (0x10 means dst[63:0] = src1[127:64] * src2[63:0]).
    // So 0x10 means src2 (poly) low 64-bits, src1 (t2) high 64-bits!
    
    // clmul takes (src1, src2, imm).
    // imm & 0x01 != 0 -> src1 high.
    // imm & 0x10 != 0 -> src2 high.
    // Wait, my clmul mapping:
    // aa = (imm & 0x01) ? a[1] : a[0] (which is src1)
    // bb = (imm & 0x10) ? b[1] : b[0] (which is src2)
    // Intel 0x10 means src2[63:0] * src1[127:64]. So src2 is low (imm&0x10 == 0), src1 is high (imm&0x01 != 0).
    // So imm should be 0x01 for Intel's 0x10 !!!
    // Let me use exact Intel semantics: 
    // pclmulqdq xmm1, xmm2, imm8
    // DEST = XMM1 * XMM2.
    // imm8[0] == 1 => XMM1[127:64] else XMM1[63:0]
    // imm8[4] == 1 => XMM2[127:64] else XMM2[63:0]
    
    // My clmul: src1=a, src2=b.
    // t3 = clmul(t2, poly, 0x01) // t2 high, poly low!
    let t3_imm = 0x01;
    let t3 = clmul(t2, poly, t3_imm);
    
    let res = veorq_u8(r_high, veorq_u8(t3, vextq_u8(t1, vdupq_n_u8(0), 8))); // srli_si128(t1, 8)

    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), vqtbl1q_u8(res, bswap));
    out
}

fn main() {
    let mut a = [0u8; 16];
    a[0] = 0x80;
    a[1] = 0x12;
    a[15] = 0x99;
    let mut b = [0u8; 16];
    b[15] = 0x01;
    b[14] = 0x34;
    b[0] = 0x77;
    
    let ghash = gf128_mul_soft(&a, &b);
    let sim = unsafe { gf128_mul_sim(&a, &b) };
    
    println!("GHASH: {:?}", ghash);
    println!("SIM:   {:?}", sim);
    assert_eq!(ghash, sim);
}
