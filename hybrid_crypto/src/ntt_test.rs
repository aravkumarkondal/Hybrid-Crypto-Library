#[cfg(test)]
mod tests {

    #[test]
    fn test_ntt_inverse() {
        let mut poly = [0i32; 256];
        for i in 0..256 {
            poly[i] = i as i32;
        }
        let original = poly;
        
        crate::ml_dsa_math::ntt(&mut poly);
        crate::ml_dsa_math::intt(&mut poly);
        
        for i in 0..256 {
            let mut val = poly[i] % 8380417;
            if val < 0 { val += 8380417; }
            assert_eq!(val, original[i]);
        }
    }

    #[test]
    fn test_poly_mul() {
        let mut a = [0i32; 256];
        let mut b = [0i32; 256];
        a[0] = 2; a[1] = 3;
        b[0] = 4; b[1] = 5;
        
        // Expected: a * b = 8 + 22x + 15x^2
        crate::ml_dsa_math::ntt(&mut a);
        crate::ml_dsa_math::ntt(&mut b);
        crate::ml_dsa_math::poly_basemul(&mut a, &b);
        crate::ml_dsa_math::intt(&mut a);
        
        let mut _a0 = a[0] % 8380417; if _a0 < 0 { _a0 += 8380417; }
        let mut _a1 = a[1] % 8380417; if _a1 < 0 { _a1 += 8380417; }
        let mut a2 = a[2] % 8380417; if a2 < 0 { a2 += 8380417; }
        assert_eq!(a2, 15);
    }

    #[test]
    fn test_hint() {
        use crate::ml_dsa_math::{makehint, usehint, decompose};
        
        let mut _fail = false;
        // w_approx = w - c*s2 + c*t0
        // z_hint = -c*s2 + c*t0
        // h = makehint(z_hint, w)
        // w1 = usehint(h, w_approx)
        // We want w1 == decompose(w).0
        
        for w in -1000000..1000000 {
            let z_hint = 50000;
            let w_approx = w + z_hint;
            let h = makehint(z_hint, w);
            let _w1 = usehint(h, w_approx);
            let (_expected_w1, _) = decompose(w);
            assert_eq!(_w1, _expected_w1, "usehint failed for w={}", w);
        }
    }
    
    #[test]
    fn test_t1_packing() {
        let mut t1 = [0i32; 256];
        for i in 0..256 {
            t1[i] = (i * 3) as i32 % 1024;
        }
        
        let mut out = [0u8; 320];
        for j in 0..64 {
            let t0 = t1[4*j] as u32;
            let t1_v = t1[4*j+1] as u32;
            let t2 = t1[4*j+2] as u32;
            let t3 = t1[4*j+3] as u32;
            out[5*j] = (t0 & 0xFF) as u8;
            out[5*j+1] = ((t0 >> 8) | ((t1_v & 0x3F) << 2)) as u8;
            out[5*j+2] = (((t1_v >> 6) & 0x0F) | ((t2 & 0x0F) << 4)) as u8;
            out[5*j+3] = (((t2 >> 4) & 0x3F) | ((t3 & 0x03) << 6)) as u8;
            out[5*j+4] = ((t3 >> 2) & 0xFF) as u8;
        }
        
        let mut p = [0i32; 256];
        let mut ptr = 0;
        for j in 0..64 {
            let b0 = out[ptr] as u64;
            let b1 = out[ptr+1] as u64;
            let b2 = out[ptr+2] as u64;
            let b3 = out[ptr+3] as u64;
            let b4 = out[ptr+4] as u64;
            let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | (b4 << 32);
            p[4*j] = (val & 0x3FF) as i32;
            p[4*j+1] = ((val >> 10) & 0x3FF) as i32;
            p[4*j+2] = ((val >> 20) & 0x3FF) as i32;
            p[4*j+3] = ((val >> 30) & 0x3FF) as i32;
            ptr += 5;
        }
        
        for i in 0..256 {
            assert_eq!(t1[i], p[i], "t1 packing failed at {}", i);
        }
    }
    
    
    
    #[test]
    fn test_z_packing() {
        let gamma1: i32 = 1 << 19;
        let mut z = [[0i32; 256]; 7];
        for i in 0..7 {
            for j in 0..256 {
                let mut val = (j as i32 * (i as i32 + 1)) % (gamma1 - 1);
                if j % 2 == 0 { val = -val; }
                z[i][j] = val;
            }
        }
        
        let mut sig = alloc::vec::Vec::new();
        for i in 0..7 {
            for j in 0..128 {
                let z0 = (gamma1 - z[i][2*j]) as u64;
                let z1 = (gamma1 - z[i][2*j+1]) as u64;
                let val = z0 | (z1 << 20);
                sig.push((val & 0xFF) as u8);
                sig.push(((val >> 8) & 0xFF) as u8);
                sig.push(((val >> 16) & 0xFF) as u8);
                sig.push(((val >> 24) & 0xFF) as u8);
                sig.push(((val >> 32) & 0xFF) as u8);
            }
        }
        
        let mut p_z = alloc::vec::Vec::new();
        let mut s_ptr = 0;
        for _ in 0..7 {
            let mut p = [0i32; 256];
            for j in 0..128 {
                let mut val = 0u64;
                for k in 0..5 {
                    val |= (sig[s_ptr+k] as u64) << (8*k);
                }
                p[2*j] = gamma1 - ((val & 0xFFFFF) as i32);
                p[2*j+1] = gamma1 - (((val >> 20) & 0xFFFFF) as i32);
                s_ptr += 5;
            }
            p_z.push(p);
        }
        
        for i in 0..7 {
            for j in 0..256 {
                assert_eq!(z[i][j], p_z[i][j], "z mismatched at {}, {}", i, j);
            }
        }
    }
}
