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

fn bit_rev(x: &[u8; 16]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for i in 0..16 {
        let mut b = x[15 - i];
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        y[i] = b;
    }
    y
}

fn main() {
    let mut a = [0u8; 16];
    a[0] = 0x80;
    a[1] = 0x12;
    let mut b = [0u8; 16];
    b[15] = 0x01;
    b[14] = 0x34;
    
    let ghash = gf128_mul_soft(&a, &b);
    let poly = polyval_mul_soft(&bit_rev(&a), &bit_rev(&b));
    let poly_rev = bit_rev(&poly);
    
    println!("GHASH:    {:?}", ghash);
    println!("POLY_REV: {:?}", poly_rev);
    assert_eq!(ghash, poly_rev);
}
