#[inline(always)]
pub fn barrett_reduce(a: i32) -> i32 {
    let q = 8380417;
    let v = ((a as i64 * 8396807) >> 46) as i32;
    let mut t = a - v * q;
    let mask_neg = t >> 31;
    t += mask_neg & q;
    let mask_pos = (q - 1 - t) >> 31;
    t -= mask_pos & q;
    t
}

pub fn poly_add_simd(a: &mut [i32; 256], b: &[i32; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] + b[i]);
    }
}

pub fn poly_sub_simd(a: &mut [i32; 256], b: &[i32; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] - b[i]);
    }
}
