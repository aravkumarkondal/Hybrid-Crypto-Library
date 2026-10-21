fn clmul(a: u64, b: u64) -> u128 {
    let mut res = 0u128;
    for i in 0..64 {
        if (a >> i) & 1 == 1 {
            res ^= (b as u128) << i;
        }
    }
    res
}

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

fn gf128_mul_clmul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut a_rev = *a; a_rev.reverse();
    let mut b_rev = *b; b_rev.reverse();
    
    let a0 = u64::from_le_bytes(a_rev[0..8].try_into().unwrap());
    let a1 = u64::from_le_bytes(a_rev[8..16].try_into().unwrap());
    let b0 = u64::from_le_bytes(b_rev[0..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(b_rev[8..16].try_into().unwrap());
    
    let x0_y0 = clmul(a0, b0);
    let x1_y1 = clmul(a1, b1);
    let x0_y1 = clmul(a0, b1);
    let x1_y0 = clmul(a1, b0);
    
    let mid = x0_y1 ^ x1_y0;
    
    let mid_low = mid << 64;
    let mid_high = mid >> 64;
    
    let r_low = x0_y0 ^ mid_low;
    let r_high = x1_y1 ^ mid_high;
    
    let poly_p = 0x00000000c2000000u64;
    
    let r_low0 = r_low as u64;
    let t1 = clmul(r_low0, poly_p);
    let t2 = r_low ^ (t1 << 64);
    
    let t2_1 = (t2 >> 64) as u64;
    let t3 = clmul(t2_1, poly_p);
    
    let res = r_high ^ t3 ^ (t1 >> 64);
    
    let mut out = res.to_le_bytes();
    out.reverse();
    out
}

fn main() {
    let mut a = [0u8; 16]; a[0] = 0x80; a[15] = 0x01;
    let mut b = [0u8; 16]; b[0] = 0x77; b[14] = 0x99;
    
    let soft = gf128_mul_soft(&a, &b);
    let clm = gf128_mul_clmul(&a, &b);
    
    println!("Soft : {:?}", soft);
    println!("CLMUL: {:?}", clm);
    assert_eq!(soft, clm, "Mismatch!");
}
