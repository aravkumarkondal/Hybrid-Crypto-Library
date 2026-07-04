type FieldElement = [u64; 4];

fn reduce(a: &mut FieldElement) {
    let c = a[3] >> 63;
    a[3] &= 0x7fffffffffffffff;
    let mut carry = 0u64;
    let (s0, c0) = a[0].overflowing_add(c * 19);
    a[0] = s0; carry = c0 as u64;
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
    
    let mut carry2 = 0u64;
    let (s0, c0) = a[0].overflowing_add(38 * carry);
    a[0] = s0;
    carry2 = c0 as u64;
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

fn main() {
    let mut a: FieldElement = [0, 0, 0, 0x8000000000000000];
    let b: FieldElement = [0, 0, 0, 0x8000000000000000];
    fadd(&mut a, &b);
    println!("2^255 + 2^255 = {:x?}", a); // Should be 38
    
    let mut a: FieldElement = [0, 0, 0, 0x8000000000000000];
    let b: FieldElement = [0, 0, 0, 0];
    fadd(&mut a, &b);
    println!("2^255 + 0 = {:x?}", a); // Should be 19
    
    let a: FieldElement = [0, 0, 0, 0x8000000000000000];
    let b: FieldElement = [0, 0, 0, 0x8000000000000000];
    let c = fmul(&a, &b);
    println!("2^255 * 2^255 = {:x?}", c); 
    // 2^510 mod P = 19 * 19 = 361
}
