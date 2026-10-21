use crate::keccak::KeccakState;
use crate::ml_dsa_math::{N, Q};

// Rejection sampling for uniform values modulo Q
pub fn sample_in_ball(rho: &[u8], c: &mut [i32; 256], tau: usize) {
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(rho);
    state.finalize();
    
    let mut sign_bytes = [0u8; 8];
    state.squeeze(&mut sign_bytes);
    
    let mut signs = 0u64;
    for i in 0..8 {
        signs |= (sign_bytes[i] as u64) << (8 * i);
    }
    
    for i in 0..N {
        c[i] = 0;
    }
    
    // Squeeze a fresh block for index sampling (separate from sign bytes)
    let mut buf = [0u8; 136];
    state.squeeze(&mut buf);
    let mut buf_pos = 0;
    
    for i in 256 - tau..256 {
        let mut j = 256;
        while j > i {
            if buf_pos >= buf.len() {
                state.squeeze(&mut buf);
                buf_pos = 0;
            }
            j = buf[buf_pos] as usize;
            buf_pos += 1;
        }
        c[i] = c[j];
        c[j] = if (signs & 1) == 1 { -1 } else { 1 };
        signs >>= 1;
    }
}

pub fn expand_a(rho: &[u8; 32], k: usize, l: usize) -> alloc::vec::Vec<alloc::vec::Vec<[i32; N]>> {
    let mut a = alloc::vec::Vec::with_capacity(k);
    for i in 0..k {
        let mut row = alloc::vec::Vec::with_capacity(l);
        for j in 0..l {
            let mut state = KeccakState::new(168, 0x1F); // SHAKE128
            state.absorb(rho);
            state.absorb(&[j as u8, i as u8]);
            state.finalize();
            
            let mut poly = [0i32; N];
            let mut count = 0;
            let mut buf = [0u8; 168];
            while count < N {
                state.squeeze(&mut buf);
                let mut pos = 0;
                while pos + 3 <= buf.len() && count < N {
                    let b0 = buf[pos] as u32;
                    let b1 = buf[pos + 1] as u32;
                    let b2 = buf[pos + 2] as u32;
                    let val = b0 | (b1 << 8) | ((b2 & 0x7F) << 16);
                    if val < Q as u32 {
                        poly[count] = val as i32;
                        count += 1;
                    }
                    pos += 3;
                }
            }
            row.push(poly);
        }
        a.push(row);
    }
    a
}

pub fn expand_s(rho_prime: &[u8; 64], l: usize, k: usize, eta: usize) -> (alloc::vec::Vec<[i32; N]>, alloc::vec::Vec<[i32; N]>) {
    let mut s1 = alloc::vec::Vec::with_capacity(l);
    let mut nonce = 0u16;
    
    for _ in 0..l {
        let mut poly = [0i32; N];
        sample_eta(rho_prime, nonce, eta, &mut poly);
        s1.push(poly);
        nonce += 1;
    }
    
    let mut s2 = alloc::vec::Vec::with_capacity(k);
    for _ in 0..k {
        let mut poly = [0i32; N];
        sample_eta(rho_prime, nonce, eta, &mut poly);
        s2.push(poly);
        nonce += 1;
    }
    (s1, s2)
}

fn sample_eta(rho_prime: &[u8; 64], nonce: u16, eta: usize, poly: &mut [i32; N]) {
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(rho_prime);
    state.absorb(&[nonce as u8, (nonce >> 8) as u8]);
    state.finalize();
    
    let mut count = 0usize;
    let mut buf = [0u8; 136];
    
    while count < 256 {
        state.squeeze(&mut buf);
        for &byte in buf.iter() {
            if count >= 256 { break; }
            let t0 = byte & 0x0F;
            let t1 = byte >> 4;
            
            if eta == 2 {
                if t0 < 15 {
                    poly[count] = 2 - (t0 as i32 % 5);
                    count += 1;
                }
                if count < 256 && t1 < 15 {
                    poly[count] = 2 - (t1 as i32 % 5);
                    count += 1;
                }
            } else {
                if t0 < 9 {
                    poly[count] = 4 - (t0 as i32);
                    count += 1;
                }
                if count < 256 && t1 < 9 {
                    poly[count] = 4 - (t1 as i32);
                    count += 1;
                }
            }
        }
    }
}


pub fn expand_mask(rho_prime: &[u8; 64], kappa: u16) -> [i32; N] {
    let mut state = KeccakState::new(136, 0x1F); // SHAKE256
    state.absorb(rho_prime);
    state.absorb(&[kappa as u8, (kappa >> 8) as u8]);
    state.finalize();
    
    let mut poly = [0i32; N];
    let mut buf = [0u8; 136];
    let mut count = 0;
    while count < N {
        state.squeeze(&mut buf);
        let mut pos = 0;
        // For ML-DSA-87, GAMMA1 = 2^19. ExpandMask uses 20 bits per coefficient (2.5 bytes)
        // Wait, gamma1 = 2^19 means values are in [-2^19, 2^19]. 
        // This spans 2 * 2^19 = 2^20 values.
        // FIPS 204 ExpandMask for gamma1 = 2^19 reads 20 bits!
        // 5 bytes = 40 bits = 2 coefficients.
        while pos + 5 <= buf.len() && count < N {
            let b0 = buf[pos] as u32;
            let b1 = buf[pos+1] as u32;
            let b2 = buf[pos+2] as u32;
            let b3 = buf[pos+3] as u32;
            let b4 = buf[pos+4] as u32;
            
            let val0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16);
            let val1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) & 0xFFFFF;
            
            poly[count] = (1 << 19) - (val0 as i32);
            count += 1;
            if count < N {
                poly[count] = (1 << 19) - (val1 as i32);
                count += 1;
            }
            pos += 5;
        }
    }
    poly
}
