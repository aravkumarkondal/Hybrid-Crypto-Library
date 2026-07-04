fn decompose(r: i32) -> (i32, i32) {
    let q = 8380417;
    let gamma2 = 261888;
    
    let mut r_plus = r % q;
    if r_plus < 0 { r_plus += q; }
    if r_plus >= q { r_plus -= q; }
    
    let alpha = 2 * gamma2;
    let v_mod = ((r_plus as i64 * 8199) >> 32) as i32;
    let mut r0 = r_plus - v_mod * alpha;
    let mask_over = ((alpha - 1 - r0) >> 31) & alpha;
    r0 -= mask_over;
    let mask_r0 = (gamma2 - r0) >> 31;
    r0 -= mask_r0 & alpha;
    
    let diff = r_plus - r0;
    let t = diff - (q - 1);
    let is_not_eq = (t | t.wrapping_neg()) >> 31;
    let mask_eq = !is_not_eq;
    
    let mut r1 = ((diff as i64 * 8201) >> 32) as i32;
    r1 = r1 & is_not_eq;
    r0 -= mask_eq & 1;
    
    (r1, r0)
}

fn ref_decompose(r: i32) -> (i32, i32) {
    let q = 8380417;
    let gamma2 = 261888;
    let alpha = 2 * gamma2;
    
    let r_plus = ((r % q) + q) % q;
    let mut r0 = r_plus % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }
    
    if r_plus - r0 == q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

fn main() {
    let mut fail = false;
    for r in -8380417..=8380417 {
        if decompose(r) != ref_decompose(r) {
            println!("Fail at r={}: got {:?}, expected {:?}", r, decompose(r), ref_decompose(r));
            fail = true;
            break;
        }
    }
    if !fail { println!("Decompose is perfectly correct!"); }
}
