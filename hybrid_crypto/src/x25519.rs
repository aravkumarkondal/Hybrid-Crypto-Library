use crate::utils::zeroize;

fn zeroize_u64_4(val: &mut [u64; 4]) {
    crate::utils::zeroize_u64(val);
}


type FieldElement = [u64; 4];

#[allow(dead_code)]
const P25519: FieldElement = [
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];

fn reduce(a: &mut FieldElement) {
    let c = a[3] >> 63;
    a[3] &= 0x7fffffffffffffff;
    let (s0, c0) = a[0].overflowing_add(c * 19);
    a[0] = s0; let mut carry = c0 as u64;
    for i in 1..4 {
        let (s, c_i) = a[i].overflowing_add(carry);
        a[i] = s; carry = c_i as u64;
    }
    
    let eq3 = (a[3] == 0x7fffffffffffffff) as u64;
    let eq2 = (a[2] == 0xffffffffffffffff) as u64;
    let eq1 = (a[1] == 0xffffffffffffffff) as u64;
    let ge0 = (a[0] >= 0xffffffffffffffed) as u64;
    let is_ge_p = (a[3] >> 63) | (eq3 & eq2 & eq1 & ge0);

    let mask_full = 0u64.wrapping_sub(is_ge_p);
    
    let (s0, c0) = a[0].overflowing_add(19 & mask_full);
    a[0] = s0;
    let mut carry2 = c0 as u64;
    for i in 1..4 {
        let (s, c_i) = a[i].overflowing_add(carry2 & mask_full);
        a[i] = s; carry2 = c_i as u64;
    }
    
    a[3] &= 0x7fffffffffffffff | (!mask_full);
}

fn fadd(a: &mut FieldElement, b: &FieldElement) {
    let mut carry = 0u64;
    for i in 0..4 {
        let (sum1, c1) = a[i].overflowing_add(b[i]);
        let (sum2, c2) = sum1.overflowing_add(carry);
        a[i] = sum2;
        carry = (c1 as u64) + (c2 as u64);
    }
    let (s0, c0) = a[0].overflowing_add(38 * carry);
    a[0] = s0;
    let mut carry2 = c0 as u64;
    for i in 1..4 {
        let (s, ci) = a[i].overflowing_add(carry2);
        a[i] = s; carry2 = ci as u64;
    }
    reduce(a);
}

fn fsub(a: &mut FieldElement, b: &FieldElement) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (diff1, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        a[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    let mask_full = 0u64.wrapping_sub(borrow);
    
    let (s0, c0) = a[0].overflowing_sub(38 & mask_full);
    a[0] = s0; 
    let mut carry = c0 as u64;
    for i in 1..4 {
        let (s, ci) = a[i].overflowing_sub(carry & mask_full);
        a[i] = s; carry = ci as u64;
    }
    reduce(a);
}

fn fmul(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let p = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = p as u64;
            carry = (p >> 64) as u64;
        }
        t[i + 4] = carry;
    }

    let mut carry = 0u64;
    for i in 0..4 {
        let p = (t[i] as u128) + (t[i+4] as u128) * 38 + (carry as u128);
        t[i] = p as u64;
        carry = (p >> 64) as u64;
    }
    
    let p0 = (t[0] as u128) + (carry as u128) * 38;
    t[0] = p0 as u64;
    carry = (p0 >> 64) as u64;
    for i in 1..4 {
        let p = (t[i] as u128) + (carry as u128);
        t[i] = p as u64;
        carry = (p >> 64) as u64;
    }
    
    let p0 = (t[0] as u128) + (carry as u128) * 38;
    t[0] = p0 as u64;
    carry = (p0 >> 64) as u64;
    for i in 1..4 {
        let p = (t[i] as u128) + (carry as u128);
        t[i] = p as u64;
        carry = (p >> 64) as u64;
    }

    let mut out = [t[0], t[1], t[2], t[3]];
    reduce(&mut out);
    out
}

fn fsqr(a: &FieldElement) -> FieldElement {
    fmul(a, a)
}


fn finv(out: &mut FieldElement, a: &FieldElement) {
    let a2 = fsqr(a);
    let mut a9 = fsqr(&a2);
    a9 = fsqr(&a9);
    a9 = fmul(&a9, a);
    let a11 = fmul(&a9, &a2);
    let a22 = fsqr(&a11);
    let a31 = fmul(&a22, &a9);

    let mut t0 = fsqr(&a31);
    for _ in 1..5 { t0 = fsqr(&t0); }
    let a_10_1 = fmul(&t0, &a31);

    t0 = fsqr(&a_10_1);
    for _ in 1..10 { t0 = fsqr(&t0); }
    let a_20_1 = fmul(&t0, &a_10_1);

    t0 = fsqr(&a_20_1);
    for _ in 1..20 { t0 = fsqr(&t0); }
    let a_40_1 = fmul(&t0, &a_20_1);

    t0 = fsqr(&a_40_1);
    for _ in 1..10 { t0 = fsqr(&t0); }
    let a_50_1 = fmul(&t0, &a_10_1);

    t0 = fsqr(&a_50_1);
    for _ in 1..50 { t0 = fsqr(&t0); }
    let a_100_1 = fmul(&t0, &a_50_1);

    t0 = fsqr(&a_100_1);
    for _ in 1..100 { t0 = fsqr(&t0); }
    let a_200_1 = fmul(&t0, &a_100_1);

    t0 = fsqr(&a_200_1);
    for _ in 1..50 { t0 = fsqr(&t0); }
    let a_250_1 = fmul(&t0, &a_50_1);

    t0 = fsqr(&a_250_1);
    for _ in 1..5 { t0 = fsqr(&t0); }
    *out = fmul(&t0, &a11);
}

pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Result<[u8; 32], crate::CryptoError> {
    let mut e = *scalar;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    let mut x1 = [0u64; 4];
    for i in 0..4 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&point[i * 8..i * 8 + 8]);
        x1[i] = u64::from_le_bytes(b);
    }
    // RFC 7748 Section 5: Implementations MUST mask the most significant bit in the final byte.
    x1[3] &= 0x7fffffffffffffff;

    let mut x2 = [1, 0, 0, 0];
    let mut z2 = [0, 0, 0, 0];
    let mut x3 = x1;
    let mut z3 = [1, 0, 0, 0];

    let mut a = [0u64; 4];
    let mut aa = [0u64; 4];
    let mut b = [0u64; 4];
    let mut bb = [0u64; 4];
    let mut c = [0u64; 4];
    let mut d = [0u64; 4];
    let mut e_field = [0u64; 4];
    let mut da = [0u64; 4];
    let mut cb = [0u64; 4];
    let mut da_plus_cb = [0u64; 4];
    let mut da_sub_cb = [0u64; 4];
    let mut temp = [0u64; 4];
    let mut aa_plus_temp = [0u64; 4];

    let mut swap = 0u64;
    for i in (0..32).rev() {
        let byte = e[i];
        for j in (0..8).rev() {
            if i == 31 && j == 7 { continue; }
            let bit = ((byte >> j) & 1) as u64;
        swap ^= bit;
        
        crate::utils::cswap(swap, &mut x2, &mut x3);
        crate::utils::cswap(swap, &mut z2, &mut z3);
        
        swap = bit;

        a = x2; fadd(&mut a, &z2);
        aa = fsqr(&a);
        b = x2; fsub(&mut b, &z2);
        bb = fsqr(&b);
        e_field = aa; fsub(&mut e_field, &bb);
        
        c = x3; fadd(&mut c, &z3);
        d = x3; fsub(&mut d, &z3);
        
        da = fmul(&d, &a);
        cb = fmul(&c, &b);
        
        da_plus_cb = da; fadd(&mut da_plus_cb, &cb);
        x3 = fsqr(&da_plus_cb);
        
        da_sub_cb = da; fsub(&mut da_sub_cb, &cb);
        z3 = fsqr(&da_sub_cb);
        z3 = fmul(&z3, &x1);
        
        x2 = fmul(&aa, &bb);
        let mut e121665 = [0u64; 4];
        e121665[0] = 121665;
        temp = fmul(&e_field, &e121665);
        aa_plus_temp = aa; fadd(&mut aa_plus_temp, &temp);
        z2 = fmul(&e_field, &aa_plus_temp);
        }
    }
    
    crate::utils::cswap(swap, &mut x2, &mut x3);
    crate::utils::cswap(swap, &mut z2, &mut z3);

    let mut inv_z2 = [0u64; 4];
    finv(&mut inv_z2, &z2);
    let mut out = fmul(&x2, &inv_z2);

    let mut res = [0u8; 32];
    let mut is_zero = 0u8;
    for i in 0..4 {
        let bytes = out[i].to_le_bytes();
        for j in 0..8 {
            res[i * 8 + j] = bytes[j];
            is_zero |= bytes[j];
        }
    }

    let result = if is_zero == 0 {
        Err(crate::CryptoError::InvalidKey)
    } else {
        Ok(res)
    };

    zeroize(&mut e);
    zeroize_u64_4(&mut x1);
    zeroize_u64_4(&mut x2);
    zeroize_u64_4(&mut x3);
    zeroize_u64_4(&mut z2);
    zeroize_u64_4(&mut z3);
    zeroize_u64_4(&mut a);
    zeroize_u64_4(&mut aa);
    zeroize_u64_4(&mut b);
    zeroize_u64_4(&mut bb);
    zeroize_u64_4(&mut c);
    zeroize_u64_4(&mut d);
    zeroize_u64_4(&mut e_field);
    zeroize_u64_4(&mut da);
    zeroize_u64_4(&mut cb);
    zeroize_u64_4(&mut da_plus_cb);
    zeroize_u64_4(&mut da_sub_cb);
    zeroize_u64_4(&mut temp);
    zeroize_u64_4(&mut aa_plus_temp);
    zeroize_u64_4(&mut inv_z2);
    zeroize_u64_4(&mut out);

    result
}

pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base_point = [0u8; 32];
    base_point[0] = 9;
    // For base point multiplication, the output cannot be zero unless the scalar is a multiple of the group order.
    // The standard scalar tweaking (e[0] &= 248, e[31] &= 127, e[31] |= 64) prevents this for the base point.
    // Therefore, unwrap is safe here.
    x25519(scalar, &base_point).unwrap()
}
