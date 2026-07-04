#![allow(unsafe_code)]

use crate::mldsa_zetas::ZETAS;

pub const Q: i32 = 8380417;
pub const D: usize = 13;
pub const N: usize = 256;
pub const GAMMA1: i32 = 1 << 19;
pub const GAMMA2: i32 = (Q - 1) / 32; // 261888

pub fn montgomery_reduce(a: i64) -> i32 {
    let u = (a as i32).wrapping_mul(4236238847u32 as i32);
    let mut t = (a + (u as i64 * Q as i64)) >> 32;
    let mask = t >> 63;
    t += mask & (Q as i64);
    t as i32
}

pub fn fqmul_std(a: i32, b: i32) -> i32 {
    let p = a as i128 * b as i128;
    let v = (p * 2201172506692i128) >> 64;
    let mut c = (p - v * 8380417) as i32;
    let mask1 = c >> 31;
    c += mask1 & Q;
    let mask2 = (Q - 1 - c) >> 31;
    c -= mask2 & Q;
    let mask3 = c >> 31;
    c += mask3 & Q;
    c
}

pub fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a as i64 * b as i64)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn fqmul_avx2(a: core::arch::x86_64::__m256i, b: i32) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::*;
    let b_vec = _mm256_set1_epi32(b);
    let qinv = _mm256_set1_epi32(4236238847u32 as i32);
    let q = _mm256_set1_epi32(Q);
    
    let a_low = _mm256_mullo_epi32(a, b_vec);
    let u = _mm256_mullo_epi32(a_low, qinv);
    
    let a_even = _mm256_mul_epi32(a, b_vec);
    let a_odd = _mm256_mul_epi32(_mm256_srli_epi64(a, 32), b_vec);
    
    let u_even = _mm256_mul_epi32(u, q);
    let u_odd = _mm256_mul_epi32(_mm256_srli_epi64(u, 32), q);
    
    let sum_even = _mm256_add_epi64(a_even, u_even);
    let sum_odd = _mm256_add_epi64(a_odd, u_odd);
    
    let res_even = _mm256_srli_epi64(sum_even, 32);
    let res = _mm256_blend_epi32(res_even, sum_odd, 0xAA);
    
    let zero = _mm256_setzero_si256();
    let cmp = _mm256_cmpgt_epi32(zero, res);
    let add_q = _mm256_and_si256(cmp, q);
    
    _mm256_add_epi32(res, add_q)
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
#[allow(dead_code)]
unsafe fn fqmul_neon(a: core::arch::aarch64::int32x4_t, b: i32) -> core::arch::aarch64::int32x4_t {
    use core::arch::aarch64::*;
    let b_vec = vdupq_n_s32(b);
    let qinv = vdupq_n_s32(4236238847u32 as i32);
    let q = vdupq_n_s32(Q);
    
    let a_low = vmulq_s32(a, b_vec);
    let u = vmulq_s32(a_low, qinv);
    
    let a_low_half = vget_low_s32(a);
    let a_high_half = vget_high_s32(a);
    let b_low_half = vget_low_s32(b_vec);
    let b_high_half = vget_high_s32(b_vec);
    
    let u_low_half = vget_low_s32(u);
    let u_high_half = vget_high_s32(u);
    let q_low_half = vget_low_s32(q);
    let q_high_half = vget_high_s32(q);
    
    let a_mul_low = vmull_s32(a_low_half, b_low_half);
    let a_mul_high = vmull_s32(a_high_half, b_high_half);
    
    let u_mul_low = vmull_s32(u_low_half, q_low_half);
    let u_mul_high = vmull_s32(u_high_half, q_high_half);
    
    let sum_low = vaddq_s64(a_mul_low, u_mul_low);
    let sum_high = vaddq_s64(a_mul_high, u_mul_high);
    
    let res_low = vshrn_n_s64(sum_low, 32);
    let res_high = vshrn_n_s64(sum_high, 32);
    
    let res = vcombine_s32(res_low, res_high);
    
    let zero = vdupq_n_s32(0);
    let cmp = vcltq_s32(res, zero);
    let add_q = vandq_s32(vreinterpretq_s32_u32(cmp), q);
    
    vaddq_s32(res, add_q)
}

pub fn barrett_reduce(a: i32) -> i32 {
    let v = ((a as i64 * 8396807) >> 46) as i32;
    let mut c = a - v * Q;
    let mask_pos = ((Q / 2) - c) >> 31;
    c -= mask_pos & Q;
    let mask_neg = (c - (-Q / 2)) >> 31;
    c += mask_neg & Q;
    c
}

pub fn mod_pm(a: i32, alpha: i32) -> i32 {
    // Constant-time modular reduction for known alpha values
    // For ML-DSA-87: alpha = 2*GAMMA2 = 523776
    // Barrett constant: floor(2^32 / 523776) = 8199
    let v = ((a as i64 * 8199) >> 32) as i32;
    let mut r = a - v * alpha;
    let mask1 = r >> 31;
    r += mask1 & alpha;
    
    let mask2 = ((alpha / 2) - r) >> 31;
    r -= mask2 & alpha;
    r
}

pub fn power2round(r: i32) -> (i32, i32) {
    let mut r_plus = r;
    let mask1 = r_plus >> 31;
    r_plus += mask1 & Q;
    let mask2 = (Q - 1 - r_plus) >> 31;
    r_plus -= mask2 & Q;
    let mask3 = r_plus >> 31;
    r_plus += mask3 & Q;

    let mut r0 = r_plus & ((1 << D) - 1);
    let mask_r0 = ((1 << (D - 1)) - r0) >> 31;
    r0 -= mask_r0 & (1 << D);
    let r1 = (r_plus - r0) >> D;
    (r1, r0)
}

pub fn decompose(r: i32) -> (i32, i32) {
    let mut r_plus = r;
    let mask1 = r_plus >> 31;
    r_plus += mask1 & Q;
    let mask2 = (Q - 1 - r_plus) >> 31;
    r_plus -= mask2 & Q;
    let mask3 = r_plus >> 31;
    r_plus += mask3 & Q;

    // Constant-time modulo: r0 = r_plus mod (2*GAMMA2) centered
    // 2*GAMMA2 = 523776. Barrett: floor(2^32 / 523776) = 8199
    let alpha = 2 * GAMMA2;
    let v_mod = ((r_plus as i64 * 8199) >> 32) as i32;
    let mut r0 = r_plus - v_mod * alpha;
    // Correct if r0 >= alpha
    let mask_over = ((alpha - 1 - r0) >> 31) & alpha;
    r0 -= mask_over;
    // Center: if r0 >= GAMMA2, subtract alpha
    let mask_r0 = (GAMMA2 - r0) >> 31;
    r0 -= mask_r0 & alpha;
    
    let diff = r_plus - r0;
    let t = diff - (Q - 1);
    let is_not_eq = (t | t.wrapping_neg()) >> 31;
    let mask_eq = !is_not_eq;
    
    // Constant-time division: r1 = diff / alpha
    // Since diff is a multiple of alpha in [0, Q-1], r1 = diff / alpha
    // Exact division multiplier: 8201 / 2^32
    let mut r1 = ((diff as i64 * 8201) >> 32) as i32;
    r1 = r1 & is_not_eq;
    r0 -= mask_eq & 1;
    
    (r1, r0)
}

pub fn highbits(r: i32) -> i32 {
    decompose(r).0
}

pub fn lowbits(r: i32) -> i32 {
    decompose(r).1
}

pub fn makehint(z: i32, r: i32) -> u8 {
    let (r1, _) = decompose(r);
    let (v1, _) = decompose(barrett_reduce(r + z));
    ((r1 ^ v1) != 0) as u8
}

pub fn usehint(h: u8, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2); // m = 16 for ML-DSA-87
    let (r1, r0) = decompose(r);
    
    // if h==1 && r0 > 0: result = (r1 + 1) % m
    let inc = (r1 + 1) - ((((r1 + 1) as u32 >= m as u32) as i32) * m);
    // if h==1 && r0 <= 0: result = (r1 - 1 + m) % m
    let dec = (r1 - 1 + m) - ((((r1 - 1 + m) as u32 >= m as u32) as i32) * m);
    
    let is_positive = (r0 > 0) as u32;
    let modified = crate::utils::ct_select_u32(dec as u32, inc as u32, is_positive) as i32;
    
    crate::utils::ct_select_u32(r1 as u32, modified as u32, h as u32) as i32
}

pub fn ntt(poly: &mut [i32; 256]) {
    let mut len = 128;
    let mut k = 1;
    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            let mut j = start;
            while j < start + len {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                if len >= 8 {
                    unsafe {
                        use core::arch::x86_64::*;
                        let p_vec = _mm256_loadu_si256(poly.as_ptr().add(j + len) as *const __m256i);
                        let t_vec = fqmul_avx2(p_vec, zeta);
                        let pj_vec = _mm256_loadu_si256(poly.as_ptr().add(j) as *const __m256i);
                        
                        let q_vec = _mm256_set1_epi32(Q);
                        let q_minus_1 = _mm256_set1_epi32(Q - 1);
                        let zero = _mm256_setzero_si256();
                        
                        let mut diff = _mm256_sub_epi32(pj_vec, t_vec);
                        let cmp = _mm256_cmpgt_epi32(zero, diff);
                        let add = _mm256_and_si256(cmp, q_vec);
                        diff = _mm256_add_epi32(diff, add);
                        _mm256_storeu_si256(poly.as_mut_ptr().add(j + len) as *mut __m256i, diff);
                        
                        let mut sum = _mm256_add_epi32(pj_vec, t_vec);
                        let cmp_sum = _mm256_cmpgt_epi32(sum, q_minus_1);
                        let sub_sum = _mm256_and_si256(cmp_sum, q_vec);
                        sum = _mm256_sub_epi32(sum, sub_sum);
                        _mm256_storeu_si256(poly.as_mut_ptr().add(j) as *mut __m256i, sum);
                    }
                    j += 8;
                    continue;
                }
                
                #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
                if len >= 4 {
                    unsafe {
                        use core::arch::aarch64::*;
                        let p_vec = vld1q_s32(poly.as_ptr().add(j + len));
                        let t_vec = fqmul_neon(p_vec, zeta);
                        let pj_vec = vld1q_s32(poly.as_ptr().add(j));
                        
                        let q_vec = vdupq_n_s32(Q);
                        let zero = vdupq_n_s32(0);
                        
                        let mut diff = vsubq_s32(pj_vec, t_vec);
                        let cmp = vcltq_s32(diff, zero);
                        let add = vandq_s32(vreinterpretq_s32_u32(cmp), q_vec);
                        diff = vaddq_s32(diff, add);
                        vst1q_s32(poly.as_mut_ptr().add(j + len), diff);
                        
                        let mut sum = vaddq_s32(pj_vec, t_vec);
                        let cmp_sum = vcgeq_s32(sum, q_vec);
                        let sub_sum = vandq_s32(vreinterpretq_s32_u32(cmp_sum), q_vec);
                        sum = vsubq_s32(sum, sub_sum);
                        vst1q_s32(poly.as_mut_ptr().add(j), sum);
                    }
                    j += 4;
                    continue;
                }

                let t = fqmul(zeta, poly[j + len]);
                poly[j + len] = barrett_reduce(poly[j] - t);
                poly[j] = barrett_reduce(poly[j] + t);
                j += 1;
            }
            start = start + 2 * len;
        }
        len >>= 1;
    }
}

pub fn intt(poly: &mut [i32; 256]) {
    let mut len = 1;
    let mut k = 255;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            let mut j = start;
            while j < start + len {
                #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
                if len >= 8 {
                    unsafe {
                        use core::arch::x86_64::*;
                        let pj_vec = _mm256_loadu_si256(poly.as_ptr().add(j) as *const __m256i);
                        let pjl_vec = _mm256_loadu_si256(poly.as_ptr().add(j + len) as *const __m256i);
                        
                        let q_vec = _mm256_set1_epi32(Q);
                        let q_minus_1 = _mm256_set1_epi32(Q - 1);
                        let zero = _mm256_setzero_si256();
                        
                        let mut sum = _mm256_add_epi32(pj_vec, pjl_vec);
                        let cmp_sum = _mm256_cmpgt_epi32(sum, q_minus_1);
                        let sub_sum = _mm256_and_si256(cmp_sum, q_vec);
                        sum = _mm256_sub_epi32(sum, sub_sum);
                        _mm256_storeu_si256(poly.as_mut_ptr().add(j) as *mut __m256i, sum);
                        
                        let mut diff = _mm256_sub_epi32(pjl_vec, pj_vec); // wait, it's poly[j + len] - t, where t = poly[j]. So pjl - pj
                        let cmp = _mm256_cmpgt_epi32(zero, diff);
                        let add = _mm256_and_si256(cmp, q_vec);
                        diff = _mm256_add_epi32(diff, add);
                        
                        let diff_mul = fqmul_avx2(diff, zeta);
                        _mm256_storeu_si256(poly.as_mut_ptr().add(j + len) as *mut __m256i, diff_mul);
                    }
                    j += 8;
                    continue;
                }
                
                #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
                if len >= 4 {
                    unsafe {
                        use core::arch::aarch64::*;
                        let pj_vec = vld1q_s32(poly.as_ptr().add(j));
                        let pjl_vec = vld1q_s32(poly.as_ptr().add(j + len));
                        
                        let q_vec = vdupq_n_s32(Q);
                        let zero = vdupq_n_s32(0);
                        
                        let mut sum = vaddq_s32(pj_vec, pjl_vec);
                        let cmp_sum = vcgeq_s32(sum, q_vec);
                        let sub_sum = vandq_s32(vreinterpretq_s32_u32(cmp_sum), q_vec);
                        sum = vsubq_s32(sum, sub_sum);
                        vst1q_s32(poly.as_mut_ptr().add(j), sum);
                        
                        let mut diff = vsubq_s32(pjl_vec, pj_vec);
                        let cmp = vcltq_s32(diff, zero);
                        let add = vandq_s32(vreinterpretq_s32_u32(cmp), q_vec);
                        diff = vaddq_s32(diff, add);
                        
                        let diff_mul = fqmul_neon(diff, zeta);
                        vst1q_s32(poly.as_mut_ptr().add(j + len), diff_mul);
                    }
                    j += 4;
                    continue;
                }

                let t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = barrett_reduce(poly[j + len] - t);
                poly[j + len] = fqmul(zeta, poly[j + len]);
                j += 1;
            }
            start = start + 2 * len;
        }
        len <<= 1;
    }
    
    let inv256 = 16382; // 256^-1 * 2^32 mod Q
    for i in 0..256 {
        poly[i] = fqmul(poly[i], inv256);
    }
}


#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
fn poly_add_wasm(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::wasm32::*;
    unsafe {
        let q_vec = i32x4_splat(Q);
        for i in (0..256).step_by(4) {
            let va = v128_load(a.as_ptr().add(i) as *const v128);
            let vb = v128_load(b.as_ptr().add(i) as *const v128);
            let mut sum = i32x4_add(va, vb);
            let cmp = i32x4_ge(sum, q_vec);
            let sub = v128_and(cmp, q_vec);
            sum = i32x4_sub(sum, sub);
            v128_store(a.as_mut_ptr().add(i) as *mut v128, sum);
        }
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
fn poly_sub_wasm(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::wasm32::*;
    unsafe {
        let q_vec = i32x4_splat(Q);
        let zero = i32x4_splat(0);
        for i in (0..256).step_by(4) {
            let va = v128_load(a.as_ptr().add(i) as *const v128);
            let vb = v128_load(b.as_ptr().add(i) as *const v128);
            let mut diff = i32x4_sub(va, vb);
            let cmp = i32x4_lt(diff, zero);
            let add = v128_and(cmp, q_vec);
            diff = i32x4_add(diff, add);
            v128_store(a.as_mut_ptr().add(i) as *mut v128, diff);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[inline(always)]
fn poly_add_avx512(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::x86_64::*;
    unsafe {
        let q_vec = _mm512_set1_epi32(Q);
        let q_minus_1 = _mm512_set1_epi32(Q - 1);
        for i in (0..256).step_by(16) {
            let va = _mm512_loadu_si512(a.as_ptr().add(i) as *const i32);
            let vb = _mm512_loadu_si512(b.as_ptr().add(i) as *const i32);
            let mut sum = _mm512_add_epi32(va, vb);
            let cmp_mask = _mm512_cmpgt_epi32_mask(sum, q_minus_1);
            sum = _mm512_mask_sub_epi32(sum, cmp_mask, sum, q_vec);
            _mm512_storeu_si512(a.as_mut_ptr().add(i) as *mut i32, sum);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[inline(always)]
fn poly_sub_avx512(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::x86_64::*;
    unsafe {
        let q_vec = _mm512_set1_epi32(Q);
        let zero = _mm512_setzero_si512();
        for i in (0..256).step_by(16) {
            let va = _mm512_loadu_si512(a.as_ptr().add(i) as *const i32);
            let vb = _mm512_loadu_si512(b.as_ptr().add(i) as *const i32);
            let mut diff = _mm512_sub_epi32(va, vb);
            let cmp_mask = _mm512_cmplt_epi32_mask(diff, zero);
            diff = _mm512_mask_add_epi32(diff, cmp_mask, diff, q_vec);
            _mm512_storeu_si512(a.as_mut_ptr().add(i) as *mut i32, diff);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
fn poly_add_avx2(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::x86_64::*;
    unsafe {
        let q_vec = _mm256_set1_epi32(Q);
        let q_minus_1 = _mm256_set1_epi32(Q - 1);
        for i in (0..256).step_by(8) {
            let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
            let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
            let mut sum = _mm256_add_epi32(va, vb);
            let cmp = _mm256_cmpgt_epi32(sum, q_minus_1);
            let sub = _mm256_and_si256(cmp, q_vec);
            sum = _mm256_sub_epi32(sum, sub);
            _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, sum);
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
fn poly_sub_avx2(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::x86_64::*;
    unsafe {
        let q_vec = _mm256_set1_epi32(Q);
        let zero = _mm256_setzero_si256();
        for i in (0..256).step_by(8) {
            let va = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
            let vb = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);
            let mut diff = _mm256_sub_epi32(va, vb);
            let cmp = _mm256_cmpgt_epi32(zero, diff);
            let add = _mm256_and_si256(cmp, q_vec);
            diff = _mm256_add_epi32(diff, add);
            _mm256_storeu_si256(a.as_mut_ptr().add(i) as *mut __m256i, diff);
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
#[allow(dead_code)]
fn poly_add_neon(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::aarch64::*;
    unsafe {
        let q_vec = vdupq_n_s32(Q);
        for i in (0..256).step_by(4) {
            let va = vld1q_s32(a.as_ptr().add(i));
            let vb = vld1q_s32(b.as_ptr().add(i));
            let mut sum = vaddq_s32(va, vb);
            let cmp = vcgeq_s32(sum, q_vec);
            let sub = vandq_s32(vreinterpretq_s32_u32(cmp), q_vec);
            sum = vsubq_s32(sum, sub);
            vst1q_s32(a.as_mut_ptr().add(i), sum);
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
#[allow(dead_code)]
fn poly_sub_neon(a: &mut [i32; 256], b: &[i32; 256]) {
    use core::arch::aarch64::*;
    unsafe {
        let q_vec = vdupq_n_s32(Q);
        let zero = vdupq_n_s32(0);
        for i in (0..256).step_by(4) {
            let va = vld1q_s32(a.as_ptr().add(i));
            let vb = vld1q_s32(b.as_ptr().add(i));
            let mut diff = vsubq_s32(va, vb);
            let cmp = vcltq_s32(diff, zero);
            let add = vandq_s32(vreinterpretq_s32_u32(cmp), q_vec);
            diff = vaddq_s32(diff, add);
            vst1q_s32(a.as_mut_ptr().add(i), diff);
        }
    }
}

#[inline(always)]
pub fn poly_add(a: &mut [i32; 256], b: &[i32; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] + b[i]);
    }
}

#[inline(always)]
pub fn poly_sub(a: &mut [i32; 256], b: &[i32; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] - b[i]);
    }
}

pub fn poly_basemul(a: &mut [i32; 256], b: &[i32; 256]) {
    for i in 0..256 {
        a[i] = fqmul_std(a[i], b[i]);
    }
}
