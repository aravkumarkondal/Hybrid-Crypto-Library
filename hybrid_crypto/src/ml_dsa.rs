#![allow(unsafe_code)]

#![allow(dead_code)]
use alloc::vec::Vec;
use crate::keccak::KeccakState;
use crate::utils::{SecretKey, zeroize};
use crate::ml_dsa_math::{N, D, GAMMA1, GAMMA2, ntt, intt, poly_add, poly_sub, poly_basemul, power2round, decompose, makehint, usehint, barrett_reduce};
use crate::ml_dsa_expand::{expand_a, expand_s, expand_mask, sample_in_ball};

pub const K: usize = 8;
pub const L: usize = 7;
pub const ETA: usize = 2;
pub const TAU: usize = 60;
pub const BETA: usize = 120;
pub const OMEGA: usize = 75;

// Hash functions
fn h(input: &[u8], out: &mut [u8; 64]) {
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(input);
    state.finalize();
    state.squeeze(out);
}

// Generate keypair
pub fn ml_dsa_87_keypair(xi: &[u8; 32]) -> (Vec<u8>, SecretKey) {
    let mut state = KeccakState::new(136, 0x1F);
    state.absorb(xi);
    // Append the standard FIPS 204 suffix (the algorithm identifier dimension K and length L)
    state.absorb(&[K as u8, L as u8]);
    state.finalize();
    let mut out = [0u8; 128];
    state.squeeze(&mut out);
    
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&out[0..32]);
    let mut rho_prime = [0u8; 64];
    rho_prime.copy_from_slice(&out[32..96]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[96..128]);
    
    let a_matrix = expand_a(&rho, K, L);
    let (s1, s2) = expand_s(&rho_prime, L, K, ETA);
    
    let mut s1_ntt = s1.clone();
    for i in 0..L { ntt(&mut s1_ntt[i]); }
    
    let mut t = Vec::with_capacity(K);
    for i in 0..K {
        let mut t_i = [0i32; N];
        for j in 0..L {
            let mut temp = s1_ntt[j];
            poly_basemul(&mut temp, &a_matrix[i][j]);
            poly_add(&mut t_i, &temp);
        }
        intt(&mut t_i);
        poly_add(&mut t_i, &s2[i]);
        t.push(t_i);
    }
    
    let mut t1 = Vec::with_capacity(K);
    let mut t0 = Vec::with_capacity(K);
    for i in 0..K {
        let mut t1_i = [0i32; N];
        let mut t0_i = [0i32; N];
        for j in 0..N {
            let (r1, r0) = power2round(t[i][j]);
            t1_i[j] = r1;
            t0_i[j] = r0;
        }
        t1.push(t1_i);
        t0.push(t0_i);
    }
    
    // In a real implementation, we would encode the keys to standard byte arrays.
    // For this zero-dependency core implementation, we will use a raw byte format
    // or just leave them as structural for now. Let's encode to bytes!
    let mut pk = Vec::with_capacity(32 + K * 320);
    pk.extend_from_slice(&rho);
    for i in 0..K {
        let mut out = [0u8; 320];
        for j in 0..64 {
            let t0 = t1[i][4*j] as u32;
            let t1_v = t1[i][4*j+1] as u32;
            let t2 = t1[i][4*j+2] as u32;
            let t3 = t1[i][4*j+3] as u32;
            out[5*j] = (t0 & 0xFF) as u8;
            out[5*j+1] = ((t0 >> 8) | ((t1_v & 0x3F) << 2)) as u8;
            out[5*j+2] = (((t1_v >> 6) & 0x0F) | ((t2 & 0x0F) << 4)) as u8;
            out[5*j+3] = (((t2 >> 4) & 0x3F) | ((t3 & 0x03) << 6)) as u8;
            out[5*j+4] = ((t3 >> 2) & 0xFF) as u8;
        }
        pk.extend_from_slice(&out);
    }
    
    let mut tr = [0u8; 64];
    h(&pk, &mut tr);
    
    let mut sk = Vec::with_capacity(4896);
    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&key);
    sk.extend_from_slice(&tr);
    // s1 (3 bits)
    for i in 0..L {
        let mut out = [0u8; 96];
        for j in 0..32 {
            let mut b = 0u32;
            for k in 0..8 {
                let val = (s1[i][8*j+k] + ETA as i32) as u32;
                b |= val << (3 * k);
            }
            out[3*j] = (b & 0xFF) as u8;
            out[3*j+1] = ((b >> 8) & 0xFF) as u8;
            out[3*j+2] = ((b >> 16) & 0xFF) as u8;
        }
        sk.extend_from_slice(&out);
    }
    // s2 (3 bits)
    for i in 0..K {
        let mut out = [0u8; 96];
        for j in 0..32 {
            let mut b = 0u32;
            for k in 0..8 {
                let val = (s2[i][8*j+k] + ETA as i32) as u32;
                b |= val << (3 * k);
            }
            out[3*j] = (b & 0xFF) as u8;
            out[3*j+1] = ((b >> 8) & 0xFF) as u8;
            out[3*j+2] = ((b >> 16) & 0xFF) as u8;
        }
        sk.extend_from_slice(&out);
    }
    // t0 (13 bits)
    for i in 0..K {
        let mut out = [0u8; 416];
        for j in 0..32 {
            // Since we need to pack 8 * 13 = 104 bits, we need u128.
            let mut b = 0u128;
            for k in 0..8 {
                let val = ((t0[i][8*j+k] + (1<<12) - 1) & 0x1FFF) as u128;
                b |= val << (13 * k);
            }
            for k in 0..13 {
                out[13*j+k] = ((b >> (8*k)) & 0xFF) as u8;
            }
        }
        sk.extend_from_slice(&out);
    }
    
    zeroize(&mut rho_prime);
    zeroize(&mut key);
    for poly in s1_ntt.iter_mut() { crate::utils::zeroize_i32(poly); }
    
    (pk, SecretKey(sk))
}

fn crh(input: &[u8], out: &mut [u8; 64]) {
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(input);
    state.finalize();
    state.squeeze(out);
}

fn inf_norm(poly: &[i32; N]) -> i32 {
    let mut max = 0;
    for &coeff in poly.iter() {
        let val = crate::ml_dsa_math::barrett_reduce(coeff);
        
        let mask_abs = val >> 31;
        let abs = (val ^ mask_abs) - mask_abs;
        
        let mask_max = (max - abs) >> 31;
        max ^= (max ^ abs) & mask_max;
    }
    max
}

fn w1_encode(w1: &Vec<[i32; N]>) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..K {
        for j in 0..(N / 2) {
            let lo = (w1[i][2 * j] & 0x0F) as u8;
            let hi = (w1[i][2 * j + 1] & 0x0F) as u8;
            out.push(lo | (hi << 4));
        }
    }
    out
}

pub fn ml_dsa_87_sign(sk: &[u8], m: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, crate::CryptoError> {
    if sk.len() != 4896 {
        return Err(crate::CryptoError::InvalidLength);
    }
    if ctx.len() > 255 {
        return Err(crate::CryptoError::InvalidLength);
    }
    // Deserialize sk (Custom raw format for zero-dependency)
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[0..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&sk[32..64]);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk[64..128]);
    
    let mut s1 = Vec::with_capacity(L);
    let mut ptr = 128;
    for _ in 0..L {
        let mut p = [0i32; N];
        for j in 0..32 {
            let b0 = sk[ptr] as u32;
            let b1 = sk[ptr+1] as u32;
            let b2 = sk[ptr+2] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16);
            for k in 0..8 {
                p[8*j+k] = ((val >> (3*k)) & 0x07) as i32 - ETA as i32;
            }
            ptr += 3;
        }
        s1.push(p);
    }
    
    let mut s2 = Vec::with_capacity(K);
    for _ in 0..K {
        let mut p = [0i32; N];
        for j in 0..32 {
            let b0 = sk[ptr] as u32;
            let b1 = sk[ptr+1] as u32;
            let b2 = sk[ptr+2] as u32;
            let val = b0 | (b1 << 8) | (b2 << 16);
            for k in 0..8 {
                p[8*j+k] = ((val >> (3*k)) & 0x07) as i32 - ETA as i32;
            }
            ptr += 3;
        }
        s2.push(p);
    }
    
    let mut t0 = Vec::with_capacity(K);
    for _ in 0..K {
        let mut p = [0i32; N];
        for j in 0..32 {
            let mut val = 0u128;
            for k in 0..13 {
                val |= (sk[ptr+k] as u128) << (8*k);
            }
            for k in 0..8 {
                let v = ((val >> (13*k)) & 0x1FFF) as i32;
                p[8*j+k] = v - (1 << 12) + 1;
            }
            ptr += 13;
        }
        t0.push(p);
    }
    
    let mut s1_ntt = s1.clone();
    for i in 0..L { ntt(&mut s1_ntt[i]); }
    let mut s2_ntt = s2.clone();
    for i in 0..K { ntt(&mut s2_ntt[i]); }
    let mut t0_ntt = t0.clone();
    for i in 0..K { ntt(&mut t0_ntt[i]); }
    
    let mut mu = [0u8; 64];
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(&tr);
    state.absorb(&[0x00, ctx.len() as u8]);
    state.absorb(ctx);
    state.absorb(m);
    state.finalize();
    state.squeeze(&mut mu);
    
    let mut rho_prime = [0u8; 64];
    let mut state = KeccakState::new(136, 0x1F);
    state.absorb(&key);
    state.absorb(rnd);
    state.absorb(&mu);
    state.finalize();
    state.squeeze(&mut rho_prime);
    
    let a_matrix = expand_a(&rho, K, L);
    let mut kappa = 0u16;
    
    loop {
        let mut y = Vec::with_capacity(L);
        for _ in 0..L {
            y.push(expand_mask(&rho_prime, kappa));
            kappa += 1;
        }
        
        let mut y_ntt = y.clone();
        for i in 0..L { ntt(&mut y_ntt[i]); }
        
        let mut w = Vec::with_capacity(K);
        for i in 0..K {
            let mut w_i = [0i32; N];
            for j in 0..L {
                let mut temp = y_ntt[j];
                poly_basemul(&mut temp, &a_matrix[i][j]);
                poly_add(&mut w_i, &temp);
            }
            intt(&mut w_i);
            w.push(w_i);
        }
        for p in y_ntt.iter_mut() { crate::utils::zeroize_i32(p); }
        
        let mut w1 = Vec::with_capacity(K);
        for i in 0..K {
            let mut w1_i = [0i32; N];
            for j in 0..N {
                let (r1, _) = decompose(w[i][j]);
                w1_i[j] = r1;
            }
            w1.push(w1_i);
        }
        
        let w1_enc = w1_encode(&w1);
        
        let mut c_tilde = [0u8; 64];
        let mut state = KeccakState::new(136, 0x1F);
        state.absorb(&mu);
        state.absorb(&w1_enc);
        state.finalize();
        state.squeeze(&mut c_tilde);
        

        let mut c_poly = [0i32; N];
        sample_in_ball(&c_tilde, &mut c_poly, TAU);
        
        let mut c_ntt = c_poly;
        ntt(&mut c_ntt);
        
        let mut reject_u8 = 0u8;
        
        // z = y + c * s1
        let mut z = Vec::with_capacity(L);
        for i in 0..L {
            let mut temp = s1_ntt[i];
            poly_basemul(&mut temp, &c_ntt);
            intt(&mut temp);
            poly_add(&mut temp, &y[i]);
            
            let over_bound = (inf_norm(&temp) >= (GAMMA1 - BETA as i32)) as u8;
            reject_u8 |= over_bound;
            z.push(temp);
        }
        
        if reject_u8 != 0 {
            for p in y.iter_mut() { crate::utils::zeroize(unsafe { core::slice::from_raw_parts_mut(p.as_mut_ptr() as *mut u8, N * 4) }); }
            continue; 
        }
        
        // r0 = LowBits(w - c * s2)
        for i in 0..K {
            let mut cs2 = s2_ntt[i];
            poly_basemul(&mut cs2, &c_ntt);
            intt(&mut cs2);
            
            let mut r0_i = [0i32; N];
            for j in 0..N {
                let diff = barrett_reduce(w[i][j] - cs2[j]);
                let (_, r0) = decompose(diff);
                r0_i[j] = r0;
            }
            let over_bound = (inf_norm(&r0_i) >= (GAMMA2 - BETA as i32)) as u8;
            reject_u8 |= over_bound;
            crate::utils::zeroize_i32(&mut cs2);
        }
        
        if reject_u8 != 0 {
            for p in y.iter_mut() { crate::utils::zeroize_i32(p); }
            continue; 
        }
        
        // Check ||c * t0||_inf
        for i in 0..K {
            let mut ct0_poly = t0_ntt[i];
            poly_basemul(&mut ct0_poly, &c_ntt);
            intt(&mut ct0_poly);
            let over_bound = (inf_norm(&ct0_poly) >= GAMMA2) as u8;
            reject_u8 |= over_bound;
        }
        
        if reject_u8 != 0 {
            for p in y.iter_mut() { crate::utils::zeroize(unsafe { core::slice::from_raw_parts_mut(p.as_mut_ptr() as *mut u8, N * 4) }); }
            continue; 
        }
        
        // Compute hints: w - c*s2 + c*t0
        let mut h_hint = Vec::with_capacity(K);
        let mut h_count = 0;
        for i in 0..K {
            let mut cs2 = s2_ntt[i];
            poly_basemul(&mut cs2, &c_ntt);
            intt(&mut cs2);
            
            let mut ct0_poly = t0_ntt[i];
            poly_basemul(&mut ct0_poly, &c_ntt);
            intt(&mut ct0_poly);
            
            let mut h_i = [0u8; N];
            for j in 0..N {
                let w_minus_cs2_plus_ct0 = barrett_reduce(w[i][j] - cs2[j] + ct0_poly[j]);
                let hint = makehint(-ct0_poly[j], w_minus_cs2_plus_ct0);
                h_i[j] = hint;
                if hint == 1 { h_count += 1; }
            }
            h_hint.push(h_i);
            crate::utils::zeroize_i32(&mut cs2);
        }
        
        if h_count > OMEGA {
            for p in y.iter_mut() { crate::utils::zeroize_i32(p); }
            continue;
        }
        
        // Pack signature: c_tilde || z || h
        let mut sig = Vec::with_capacity(4627);
        sig.extend_from_slice(&c_tilde);
        for i in 0..L {
            for j in 0..128 { // 256 / 2
                let z0 = (GAMMA1 - z[i][2*j]) as u64;
                let z1 = (GAMMA1 - z[i][2*j+1]) as u64;
                let val = z0 | (z1 << 20);
                sig.push((val & 0xFF) as u8);
                sig.push(((val >> 8) & 0xFF) as u8);
                sig.push(((val >> 16) & 0xFF) as u8);
                sig.push(((val >> 24) & 0xFF) as u8);
                sig.push(((val >> 32) & 0xFF) as u8);
            }
        }
        
        let mut h_enc = alloc::vec![0u8; OMEGA + K];
        let mut index = 0;
        for i in 0..K {
            for j in 0..N {
                if h_hint[i][j] == 1 {
                    h_enc[index] = j as u8;
                    index += 1;
                }
            }
            h_enc[OMEGA + i] = index as u8;
        }
        sig.extend_from_slice(&h_enc);
        
        zeroize(&mut rho_prime);
        for p in s1.iter_mut() { crate::utils::zeroize_i32(p); }
        for p in s2.iter_mut() { crate::utils::zeroize_i32(p); }
        for p in y.iter_mut() { crate::utils::zeroize_i32(p); }
        for p in s1_ntt.iter_mut() { crate::utils::zeroize_i32(p); }
        for p in s2_ntt.iter_mut() { crate::utils::zeroize_i32(p); }
        for p in t0_ntt.iter_mut() { crate::utils::zeroize_i32(p); }
        
        return Ok(sig);
    }
}

pub fn ml_dsa_87_verify(pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    if pk.len() != 2592 || sig.len() != 4627 {
        return false;
    }
    if ctx.len() > 255 {
        return false;
    }

    let mut is_valid = true;

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[0..32]);
    
    let mut t1 = Vec::with_capacity(K);
    let mut ptr = 32;
    for _ in 0..K {
        let mut p = [0i32; N];
        for j in 0..64 {
            let b0 = pk[ptr] as u64;
            let b1 = pk[ptr+1] as u64;
            let b2 = pk[ptr+2] as u64;
            let b3 = pk[ptr+3] as u64;
            let b4 = pk[ptr+4] as u64;
            let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32);
            p[4*j] = (val & 0x3FF) as i32;
            p[4*j+1] = ((val >> 10) & 0x3FF) as i32;
            p[4*j+2] = ((val >> 20) & 0x3FF) as i32;
            p[4*j+3] = ((val >> 30) & 0x3FF) as i32;
            ptr += 5;
        }
        t1.push(p);
    }
    
    let mut c_tilde = [0u8; 64];
    c_tilde.copy_from_slice(&sig[0..64]);
    
    let mut z = Vec::with_capacity(L);
    let mut s_ptr = 64;
    for _ in 0..L {
        let mut p = [0i32; N];
        for j in 0..128 {
            let mut val = 0u64;
            for k in 0..5 {
                val |= (sig[s_ptr+k] as u64) << (8*k);
            }
            p[2*j] = GAMMA1 - ((val & 0xFFFFF) as i32);
            p[2*j+1] = GAMMA1 - (((val >> 20) & 0xFFFFF) as i32);
            s_ptr += 5;
        }
        if inf_norm(&p) >= (GAMMA1 - BETA as i32) {
            is_valid = false;
        }
        z.push(p);
    }
    
    let mut h_hint = Vec::with_capacity(K);
    let mut h_enc = [0u8; OMEGA + K];
    h_enc.copy_from_slice(&sig[s_ptr..s_ptr + OMEGA + K]);
    
    let mut idx = 0;
    for i in 0..K {
        let mut p = [0u8; N];
        let bound = h_enc[OMEGA + i];
        if bound < idx || bound > OMEGA as u8 {
            is_valid = false;
        }
        let mut prev_hint_pos: i32 = -1;
        // To be constant time, we should iterate a fixed number of times (OMEGA)
        // or just bound up to OMEGA. Actually, since h_enc can have arbitrary values,
        // we can iterate through the available space, but we must keep it constant time.
        // The easiest constant time for this hint decode loop is to iterate up to OMEGA
        // but only process if we haven't hit the bound.
        for _ in 0..OMEGA {
            if idx < bound {
                let pos = h_enc[idx as usize] as i32;
                if pos <= prev_hint_pos {
                    is_valid = false;
                } else {
                    p[pos as usize] = 1;
                    prev_hint_pos = pos;
                }
                idx += 1;
            }
        }
        h_hint.push(p);
    }
    let h_weight = idx;
    
    // Verify remaining bytes are exactly zero
    for _ in 0..OMEGA {
        if idx < OMEGA as u8 {
            if h_enc[idx as usize] != 0 {
                is_valid = false;
            }
            idx += 1;
        }
    }
    
    if usize::from(h_weight) > OMEGA {
        is_valid = false;
    }
    
    let mut tr = [0u8; 64];
    h(pk, &mut tr);
    
    let mut mu = [0u8; 64];
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(&tr);
    state.absorb(&[0x00, ctx.len() as u8]);
    state.absorb(ctx);
    state.absorb(m);
    state.finalize();
    state.squeeze(&mut mu);
    
    let mut c_poly = [0i32; N];
    sample_in_ball(&c_tilde, &mut c_poly, TAU);
    let mut c_ntt = c_poly;
    ntt(&mut c_ntt);
    
    let a_matrix = expand_a(&rho, K, L);
    
    let mut z_ntt = z.clone();
    for i in 0..L { ntt(&mut z_ntt[i]); }
    
    let mut t1_ntt = t1.clone();
    for i in 0..K {
        for j in 0..N {
            // t1 is multiplied by 2^D before multiplying by c
            t1_ntt[i][j] = barrett_reduce(t1_ntt[i][j] * (1 << D));
        }
        ntt(&mut t1_ntt[i]);
    }
    
    let mut w_approx = Vec::with_capacity(K);
    for i in 0..K {
        let mut w_i = [0i32; N];
        for j in 0..L {
            let mut temp = z_ntt[j];
            poly_basemul(&mut temp, &a_matrix[i][j]);
            poly_add(&mut w_i, &temp);
        }
        
        let mut ct1 = t1_ntt[i];
        poly_basemul(&mut ct1, &c_ntt);
        poly_sub(&mut w_i, &ct1);
        intt(&mut w_i);
        w_approx.push(w_i);
    }
    
    let mut w1 = Vec::with_capacity(K);
    for i in 0..K {
        let mut w1_i = [0i32; N];
        for j in 0..N {
            w1_i[j] = usehint(h_hint[i][j], w_approx[i][j]);
        }
        w1.push(w1_i);
    }
    
    let w1_enc = w1_encode(&w1);
    
    let mut c_tilde_prime = [0u8; 64];
    let mut state = KeccakState::new(136, 0x1F);
    state.absorb(&mu);
    state.absorb(&w1_enc);
    state.finalize();
    state.squeeze(&mut c_tilde_prime);
    
    let eq = crate::utils::constant_time_eq(&c_tilde, &c_tilde_prime);
    is_valid && eq
}
