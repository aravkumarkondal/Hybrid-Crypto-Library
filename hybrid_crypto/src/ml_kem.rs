#![allow(unsafe_code)]

#![allow(dead_code)]
use crate::utils::{zeroize, constant_time_eq};

pub const K: usize = 3;
pub const N: usize = 256;
pub const Q: i32 = 3329;
const ZETAS: [i16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 
    2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 
    1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 
    2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 
    1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 
    2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154, 
];

fn fqmul(a: i16, b: i16) -> i16 {
    let p = a as i32 * b as i32;
    let v = ((p as i64 * 20159) >> 26) as i32;
    let mut res = p - v * Q;
    
    let mask_neg = res >> 31;
    res += mask_neg & Q;
    
    let mask_pos = (3328 - res) >> 31;
    res -= mask_pos & Q;
    
    res as i16
}

fn barrett_reduce(a: i16) -> i16 {
    let p = a as i32;
    let v = (p * 20159) >> 26;
    let mut res = p - v * Q;
    
    let mask_neg = res >> 31;
    res += mask_neg & Q;
    
    let mask_pos = (3328 - res) >> 31;
    res -= mask_pos & Q;
    
    res as i16
}

fn zeroize_poly(poly: &mut [i16; 256]) {
    for val in poly.iter_mut() {
        unsafe { core::ptr::write_volatile(val, 0); }
    }
}

pub fn ntt(poly: &mut [i16; 256]) {
    let mut len = 128;
    let mut k = 1;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, poly[j + len]);
                poly[j + len] = barrett_reduce(poly[j] - t);
                poly[j] = barrett_reduce(poly[j] + t);
            }
            start = start + 2 * len;
        }
        len >>= 1;
    }
}

pub fn intt(poly: &mut [i16; 256]) {
    let mut len = 2;
    let mut k = 127;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = poly[j];
                poly[j] = barrett_reduce(t + poly[j + len]);
                poly[j + len] = barrett_reduce(poly[j + len] - t);
                poly[j + len] = fqmul(zeta, poly[j + len]);
            }
            start = start + 2 * len;
        }
        len <<= 1;
    }
    let f = 3303; // 128^-1 mod 3329
    for i in 0..256 {
        poly[i] = fqmul(poly[i], f);
    }
}

pub fn poly_add(a: &mut [i16; 256], b: &[i16; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] + b[i]);
    }
}

pub fn poly_sub(a: &mut [i16; 256], b: &[i16; 256]) {
    for i in 0..256 {
        a[i] = barrett_reduce(a[i] - b[i]);
    }
}

pub fn poly_basemul(a: &mut [i16; 256], b: &[i16; 256]) {
    for i in 0..64 {
        let r0 = fqmul(a[4 * i + 1], b[4 * i + 1]);
        let a0 = fqmul(a[4 * i + 0], b[4 * i + 0]) + fqmul(r0, ZETAS[64 + i]);
        let a1 = fqmul(a[4 * i + 0], b[4 * i + 1]) + fqmul(a[4 * i + 1], b[4 * i + 0]);
        
        let r2 = fqmul(a[4 * i + 3], b[4 * i + 3]);
        let a2 = fqmul(a[4 * i + 2], b[4 * i + 2]) - fqmul(r2, ZETAS[64 + i]);
        let a3 = fqmul(a[4 * i + 2], b[4 * i + 3]) + fqmul(a[4 * i + 3], b[4 * i + 2]);

        a[4 * i + 0] = barrett_reduce(a0);
        a[4 * i + 1] = barrett_reduce(a1);
        a[4 * i + 2] = barrett_reduce(a2);
        a[4 * i + 3] = barrett_reduce(a3);
    }
}

// ==========================================
// FIPS 203 Byte Encoding & Compression
// ==========================================

fn rem_euclid_q(x: i16) -> i16 {
    barrett_reduce(x)
}

pub fn compress_q(x: i16, d: usize) -> u16 {
    let x_u32 = rem_euclid_q(x) as u32;
    let a = x_u32 << d;
    let val = a * 2 + 3329;
    let res = ((val as u64 * 10321339) >> 36) as u16;
    res & ((1 << d) - 1)
}

pub fn decompress_q(x: u16, d: usize) -> i16 {
    let x_u32 = x as u32;
    let res = (x_u32 * 3329 + (1 << (d - 1))) >> d;
    res as i16
}

pub fn byte_encode_1(f: &[i16; 256], out: &mut [u8; 32]) {
    for i in 0..32 {
        let mut b = 0u8;
        for j in 0..8 {
            b |= (f[i * 8 + j] as u8 & 1) << j;
        }
        out[i] = b;
    }
}

pub fn byte_decode_1(b: &[u8; 32], f: &mut [i16; 256]) {
    for i in 0..32 {
        for j in 0..8 {
            f[i * 8 + j] = ((b[i] >> j) & 1) as i16;
        }
    }
}

pub fn byte_encode_4(f: &[i16; 256], out: &mut [u8; 128]) {
    for i in 0..128 {
        let f0 = (f[2 * i] as u8) & 0x0F;
        let f1 = (f[2 * i + 1] as u8) & 0x0F;
        out[i] = f0 | (f1 << 4);
    }
}

pub fn byte_decode_4(b: &[u8; 128], f: &mut [i16; 256]) {
    for i in 0..128 {
        f[2 * i] = (b[i] & 0x0F) as i16;
        f[2 * i + 1] = (b[i] >> 4) as i16;
    }
}

pub fn byte_encode_10(f: &[i16; 256], out: &mut [u8; 320]) {
    for i in 0..64 {
        let f0 = f[4 * i] as u32;
        let f1 = f[4 * i + 1] as u32;
        let f2 = f[4 * i + 2] as u32;
        let f3 = f[4 * i + 3] as u32;
        
        out[5 * i] = (f0 & 0xFF) as u8;
        out[5 * i + 1] = ((f0 >> 8) | ((f1 & 0x3F) << 2)) as u8;
        out[5 * i + 2] = (((f1 >> 6) & 0x0F) | ((f2 & 0x0F) << 4)) as u8;
        out[5 * i + 3] = (((f2 >> 4) & 0x3F) | ((f3 & 0x03) << 6)) as u8;
        out[5 * i + 4] = ((f3 >> 2) & 0xFF) as u8;
    }
}

pub fn byte_decode_10(b: &[u8; 320], f: &mut [i16; 256]) {
    for i in 0..64 {
        let b0 = b[5 * i] as u32;
        let b1 = b[5 * i + 1] as u32;
        let b2 = b[5 * i + 2] as u32;
        let b3 = b[5 * i + 3] as u32;
        let b4 = b[5 * i + 4] as u32;
        
        f[4 * i] = (b0 | ((b1 & 0x03) << 8)) as i16;
        f[4 * i + 1] = (((b1 >> 2) & 0x3F) | ((b2 & 0x0F) << 6)) as i16;
        f[4 * i + 2] = (((b2 >> 4) & 0x0F) | ((b3 & 0x3F) << 4)) as i16;
        f[4 * i + 3] = (((b3 >> 6) & 0x03) | (b4 << 2)) as i16;
    }
}

pub fn byte_encode_12(f: &[i16; 256], out: &mut [u8; 384]) {
    for i in 0..128 {
        let f0 = rem_euclid_q(f[2 * i]) as u16 as u32;
        let f1 = rem_euclid_q(f[2 * i + 1]) as u16 as u32;
        
        out[3 * i] = (f0 & 0xFF) as u8;
        out[3 * i + 1] = (((f0 >> 8) & 0x0F) | ((f1 & 0x0F) << 4)) as u8;
        out[3 * i + 2] = ((f1 >> 4) & 0xFF) as u8;
    }
}

pub fn byte_decode_12(b: &[u8; 384], f: &mut [i16; 256]) {
    for i in 0..128 {
        let b0 = b[3 * i] as u32;
        let b1 = b[3 * i + 1] as u32;
        let b2 = b[3 * i + 2] as u32;
        
        f[2 * i] = (b0 | ((b1 & 0x0F) << 8)) as i16;
        f[2 * i + 1] = (((b1 >> 4) & 0x0F) | (b2 << 4)) as i16;
    }
}

// ==========================================
// FIPS 203 Polynomial Sampling
// ==========================================

use crate::keccak::{prf_eta2, xof};

pub fn sample_ntt(rho: &[u8; 32], i: u8, j: u8, a: &mut [i16; 256]) {
    let mut x = xof(rho, i, j);
    let mut count = 0;
    let mut buf = [0u8; 3];
    
    while count < 256 {
        x.squeeze_bytes(&mut buf);
        let b0 = buf[0] as u32;
        let b1 = buf[1] as u32;
        let b2 = buf[2] as u32;
        
        let d1 = b0 | ((b1 & 0x0F) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);
        
        let valid1 = (d1 < 3329) as usize;
        if count < 256 {
            a[count] = d1 as i16;
            count += valid1;
        }
        
        let valid2 = (d2 < 3329) as usize;
        if count < 256 {
            a[count] = d2 as i16;
            count += valid2;
        }
    }
}

pub fn sample_poly_cbd2(s: &[u8; 32], b: u8, f: &mut [i16; 256]) {
    let prf_out = prf_eta2(s, b); // 128 bytes
    for i in 0..128 {
        let byte = prf_out[i];
        for j in 0..2 {
            let bits = (byte >> (4 * j)) & 0x0F;
            let x = (bits & 1) + ((bits >> 1) & 1);
            let y = ((bits >> 2) & 1) + ((bits >> 3) & 1);
            f[2 * i + j] = (x as i16) - (y as i16);
        }
    }
}


// ==========================================
// K-PKE (Public Key Encryption)
// ==========================================

use crate::keccak::{g, h, j};

pub fn k_pke_keygen(d: &[u8; 32]) -> ([u8; 1184], [u8; 1152]) {
    let mut pk = [0u8; 1184];
    let mut sk = [0u8; 1152];
    
    let mut g_out = g(d);
    let rho = &g_out[0..32];
    let sigma = &g_out[32..64];
    
    let mut rho_arr = [0u8; 32];
    rho_arr.copy_from_slice(rho);
    let mut a_matrix = [[[0i16; 256]; K]; K];
    for i in 0..K {
        for j in 0..K {
            // FIPS 203 Section 5.1: A_{i,j} = SampleNTT(rho, j, i)
            sample_ntt(&rho_arr, j as u8, i as u8, &mut a_matrix[i][j]);
        }
    }
    
    let mut sigma_arr = [0u8; 32];
    sigma_arr.copy_from_slice(sigma);
    
    let mut s = [[0i16; 256]; K];
    let mut e = [[0i16; 256]; K];
    let mut nonce = 0u8;
    
    for i in 0..K {
        sample_poly_cbd2(&sigma_arr, nonce, &mut s[i]);
        nonce += 1;
    }
    for i in 0..K {
        sample_poly_cbd2(&sigma_arr, nonce, &mut e[i]);
        nonce += 1;
    }
    
    for i in 0..K {
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }
    
    let mut t = [[0i16; 256]; K];
    for i in 0..K {
        for j in 0..K {
            let mut temp = s[j];
            poly_basemul(&mut temp, &a_matrix[i][j]);
            poly_add(&mut t[i], &temp);
        }
        poly_add(&mut t[i], &e[i]);
    }
    
    for i in 0..K {
        let mut t_encoded = [0u8; 384];
        byte_encode_12(&t[i], &mut t_encoded);
        pk[i * 384..(i + 1) * 384].copy_from_slice(&t_encoded);
    }
    pk[1152..1184].copy_from_slice(rho);
    
    for i in 0..K {
        let mut s_encoded = [0u8; 384];
        byte_encode_12(&s[i], &mut s_encoded);
        sk[i * 384..(i + 1) * 384].copy_from_slice(&s_encoded);
    }
    
    zeroize(&mut g_out);
    for i in 0..K {
        zeroize_poly(&mut s[i]);
        zeroize_poly(&mut e[i]);
    }
    
    (pk, sk)
}

pub fn k_pke_encrypt(pk: &[u8; 1184], m: &[u8; 32], r: &[u8; 32]) -> Result<[u8; 1088], crate::CryptoError> {
    let mut t = [[0i16; 256]; K];
    for i in 0..K {
        let mut t_encoded = [0u8; 384];
        t_encoded.copy_from_slice(&pk[i * 384..(i + 1) * 384]);
        byte_decode_12(&t_encoded, &mut t[i]);
        for j in 0..256 {
            if t[i][j] >= Q as i16 {
                return Err(crate::CryptoError::InvalidKey);
            }
        }
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[1152..1184]);
    
    let mut a_matrix = [[[0i16; 256]; K]; K];
    for i in 0..K {
        for j in 0..K {
            // FIPS 203 Section 5.2: A_{i,j} = SampleNTT(rho, j, i)
            sample_ntt(&rho, j as u8, i as u8, &mut a_matrix[i][j]);
        }
    }
    
    let mut y = [[0i16; 256]; K];
    let mut e1 = [[0i16; 256]; K];
    let mut e2 = [0i16; 256];
    let mut nonce = 0u8;
    
    for i in 0..K {
        sample_poly_cbd2(r, nonce, &mut y[i]);
        nonce += 1;
    }
    for i in 0..K {
        sample_poly_cbd2(r, nonce, &mut e1[i]);
        nonce += 1;
    }
    sample_poly_cbd2(r, nonce, &mut e2);
    
    for i in 0..K {
        ntt(&mut y[i]);
    }
    
    let mut u = [[0i16; 256]; K];
    for i in 0..K {
        for j in 0..K {
            let mut temp = y[j];
            poly_basemul(&mut temp, &a_matrix[j][i]); // A^T
            poly_add(&mut u[i], &temp);
        }
        intt(&mut u[i]);
        poly_add(&mut u[i], &e1[i]);
    }
    
    let mut v = [0i16; 256];
    for j in 0..K {
        let mut temp = y[j];
        poly_basemul(&mut temp, &t[j]);
        poly_add(&mut v, &temp);
    }
    intt(&mut v);
    poly_add(&mut v, &e2);
    
    let mut msg_poly = [0i16; 256];
    byte_decode_1(m, &mut msg_poly);
    for i in 0..256 {
        msg_poly[i] = decompress_q(msg_poly[i] as u16, 1);
    }
    poly_add(&mut v, &msg_poly);
    
    let mut c = [0u8; 1088];
    for i in 0..K {
        for j in 0..256 {
            u[i][j] = compress_q(u[i][j], 10) as i16;
        }
        let mut u_encoded = [0u8; 320];
        byte_encode_10(&u[i], &mut u_encoded);
        c[i * 320..(i + 1) * 320].copy_from_slice(&u_encoded);
    }
    
    for j in 0..256 {
        v[j] = compress_q(v[j], 4) as i16;
    }
    let mut v_encoded = [0u8; 128];
    byte_encode_4(&v, &mut v_encoded);
    c[960..1088].copy_from_slice(&v_encoded);
    
    for i in 0..K {
        zeroize_poly(&mut y[i]);
        zeroize_poly(&mut e1[i]);
    }
    zeroize_poly(&mut e2);
    
    Ok(c)
}

pub fn k_pke_decrypt(sk: &[u8; 1152], c: &[u8; 1088]) -> [u8; 32] {
    let mut u = [[0i16; 256]; K];
    for i in 0..K {
        let mut u_encoded = [0u8; 320];
        u_encoded.copy_from_slice(&c[i * 320..(i + 1) * 320]);
        byte_decode_10(&u_encoded, &mut u[i]);
        for j in 0..256 {
            u[i][j] = decompress_q(u[i][j] as u16, 10);
        }
    }
    
    let mut v = [0i16; 256];
    let mut v_encoded = [0u8; 128];
    v_encoded.copy_from_slice(&c[960..1088]);
    byte_decode_4(&v_encoded, &mut v);
    for j in 0..256 {
        v[j] = decompress_q(v[j] as u16, 4);
    }
    
    let mut s = [[0i16; 256]; K];
    for i in 0..K {
        let mut s_encoded = [0u8; 384];
        s_encoded.copy_from_slice(&sk[i * 384..(i + 1) * 384]);
        byte_decode_12(&s_encoded, &mut s[i]);
    }
    
    for i in 0..K {
        ntt(&mut u[i]);
    }
    
    let mut s_dot_u = [0i16; 256];
    for i in 0..K {
        let mut temp = u[i];
        poly_basemul(&mut temp, &s[i]);
        poly_add(&mut s_dot_u, &temp);
    }
    intt(&mut s_dot_u);
    
    poly_sub(&mut v, &s_dot_u);
    
    for j in 0..256 {
        v[j] = compress_q(v[j], 1) as i16;
    }
    
    let mut m = [0u8; 32];
    byte_encode_1(&v, &mut m);
    
    for i in 0..K {
        zeroize_poly(&mut s[i]);
    }
    zeroize_poly(&mut s_dot_u);
    
    m
}



// ==========================================
// ML-KEM (FO Transform)
// ==========================================

pub fn ml_kem_768_keypair(entropy: &[u8; 64]) -> ([u8; 1184], [u8; 2400]) {
    let mut d = [0u8; 32];
    d.copy_from_slice(&entropy[0..32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&entropy[32..64]);
    
    let (pk, sk_pke) = k_pke_keygen(&d);
    
    let mut sk = [0u8; 2400];
    sk[0..1152].copy_from_slice(&sk_pke);
    sk[1152..2336].copy_from_slice(&pk);
    
    let pk_hash = h(&pk);
    sk[2336..2368].copy_from_slice(&pk_hash);
    sk[2368..2400].copy_from_slice(&z);
    
    zeroize(&mut d);
    zeroize(&mut z);
    
    (pk, sk)
}

pub fn ml_kem_768_encapsulate(pub_key: &[u8; 1184], entropy: &[u8; 32]) -> Result<([u8; 1088], [u8; 32]), crate::CryptoError> {
    let mut m = [0u8; 32];
    m.copy_from_slice(entropy);
    
    let mut g_input = [0u8; 64];
    g_input[0..32].copy_from_slice(&m);
    g_input[32..64].copy_from_slice(&h(pub_key));
    
    let mut g_out = g(&g_input);
    let mut k = [0u8; 32];
    k.copy_from_slice(&g_out[0..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g_out[32..64]);
    
    let c = match k_pke_encrypt(pub_key, &m, &r) {
        Ok(ct) => ct,
        Err(e) => {
            zeroize(&mut m);
            zeroize(&mut g_input);
            zeroize(&mut g_out);
            zeroize(&mut r);
            return Err(e);
        }
    };
    
    zeroize(&mut m);
    zeroize(&mut g_input);
    zeroize(&mut g_out);
    zeroize(&mut r);
    
    Ok((c, k))
}

pub fn ml_kem_768_decapsulate(priv_key: &[u8; 2400], ciphertext: &[u8; 1088]) -> [u8; 32] {
    let mut sk_pke = [0u8; 1152];
    sk_pke.copy_from_slice(&priv_key[0..1152]);
    
    let mut pk = [0u8; 1184];
    pk.copy_from_slice(&priv_key[1152..2336]);
    
    let mut h_pk = [0u8; 32];
    h_pk.copy_from_slice(&priv_key[2336..2368]);
    
    let mut z = [0u8; 32];
    z.copy_from_slice(&priv_key[2368..2400]);
    
    let mut m_prime = k_pke_decrypt(&sk_pke, ciphertext);
    
    let mut g_input = [0u8; 64];
    g_input[0..32].copy_from_slice(&m_prime);
    g_input[32..64].copy_from_slice(&h_pk);
    
    let mut g_out = g(&g_input);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_out[0..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g_out[32..64]);
    
    let mut j_input = [0u8; 1120]; // 32 + 1088 = 1120
    j_input[0..32].copy_from_slice(&z);
    j_input[32..1120].copy_from_slice(ciphertext);
    let mut k_bar = j(&j_input);
    
    let (mut c_prime, encrypt_ok) = match k_pke_encrypt(&pk, &m_prime, &r_prime) {
        Ok(c) => (c, 1u8),
        Err(_) => ([0u8; 1088], 0u8),
    };
    
    // Constant-time comparison
    let is_valid = (constant_time_eq(ciphertext, &c_prime) as u8) & encrypt_ok;
    
    let mut shared_secret = [0u8; 32];
    for i in 0..4 {
        let mut k_bar_chunk = [0u8; 8];
        k_bar_chunk.copy_from_slice(&k_bar[i*8..(i+1)*8]);
        let mut k_prime_chunk = [0u8; 8];
        k_prime_chunk.copy_from_slice(&k_prime[i*8..(i+1)*8]);
        
        let a = u64::from_le_bytes(k_bar_chunk);
        let b = u64::from_le_bytes(k_prime_chunk);
        let res = crate::utils::ct_select_u64(a, b, is_valid);
        
        shared_secret[i*8..(i+1)*8].copy_from_slice(&res.to_le_bytes());
    }
    
    zeroize(&mut sk_pke);
    zeroize(&mut m_prime);
    zeroize(&mut k_prime);
    zeroize(&mut z);
    zeroize(&mut g_input);
    zeroize(&mut g_out);
    zeroize(&mut r_prime);
    zeroize(&mut j_input);
    zeroize(&mut k_bar);
    zeroize(&mut c_prime);
    
    shared_secret
}
