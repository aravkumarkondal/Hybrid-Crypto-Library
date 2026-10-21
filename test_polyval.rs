use std::arch::aarch64::*;

// GHASH soft implementation
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

// POLYVAL soft implementation
fn polyval_mul_soft(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *b;
    for i in 0..16 {
        for bit in 0..8 {
            let mask = 0u8.wrapping_sub((a[i] >> bit) & 1);
            for j in 0..16 { z[j] ^= v[j] & mask; }
            let msb = v[15] >> 7;
            for j in (0..15).rev() { v[j + 1] = (v[j + 1] << 1) | (v[j] >> 7); }
            v[0] <<= 1;
            v[0] ^= 0xC2 & (0u8.wrapping_sub(msb));
        }
    }
    z
}

fn rev(x: &[u8; 16]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for i in 0..16 { y[i] = x[15 - i]; }
    y
}

fn main() {
    let mut a = [0u8; 16];
    a[0] = 0x80;
    let mut b = [0u8; 16];
    b[15] = 0x01;
    
    let ghash = gf128_mul_soft(&a, &b);
    let poly = polyval_mul_soft(&rev(&a), &rev(&b));
    let poly_rev = rev(&poly);
    
    println!("GHASH:    {:?}", ghash);
    println!("POLY_REV: {:?}", poly_rev);
}
