use crate::sha2::Sha256;

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    let mut hashed_key = [0u8; 32];
    
    if key.len() > 64 {
        let mut key_sha = crate::sha2::Sha256::new();
        key_sha.update(key);
        hashed_key = key_sha.finalize();
        k_block[..32].copy_from_slice(&hashed_key);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut i_key_pad = [0x36u8; 64];
    let mut o_key_pad = [0x5cu8; 64];
    
    for i in 0..64 {
        i_key_pad[i] ^= k_block[i];
        o_key_pad[i] ^= k_block[i];
    }
    
    let mut inner_sha = crate::sha2::Sha256::new();
    inner_sha.update(&i_key_pad);
    inner_sha.update(data);
    let mut inner_hash = inner_sha.finalize();
    
    let mut outer_sha = crate::sha2::Sha256::new();
    outer_sha.update(&o_key_pad);
    outer_sha.update(&inner_hash);
    let res = outer_sha.finalize();
    
    crate::utils::zeroize(&mut k_block);
    crate::utils::zeroize(&mut i_key_pad);
    crate::utils::zeroize(&mut o_key_pad);
    crate::utils::zeroize(&mut inner_hash);
    crate::utils::zeroize(&mut hashed_key);
    
    res
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let actual_salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    hmac_sha256(actual_salt, ikm)
}

pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], okm: &mut [u8]) {
    assert!(okm.len() <= 255 * 32, "OKM length exceeds RFC 5869 limits");
    let mut t = [0u8; 32];
    let mut t_len = 0;
    let mut okm_offset = 0;
    let mut counter = 1u8;

    while okm_offset < okm.len() {
        let mut k_block = [0u8; 64];
        k_block[..32].copy_from_slice(prk);

        let mut o_key_pad = [0x5c; 64];
        let mut i_key_pad = [0x36; 64];
        for i in 0..64 {
            o_key_pad[i] ^= k_block[i];
            i_key_pad[i] ^= k_block[i];
        }

        let mut inner_sha = Sha256::new();
        inner_sha.update(&i_key_pad);
        if t_len > 0 {
            inner_sha.update(&t);
        }
        inner_sha.update(info);
        inner_sha.update(&[counter]);
        let mut inner_hash = inner_sha.finalize();

        let mut outer_sha = Sha256::new();
        outer_sha.update(&o_key_pad);
        outer_sha.update(&inner_hash);
        t = outer_sha.finalize();
        t_len = 32;

        let to_copy = core::cmp::min(32, okm.len() - okm_offset);
        okm[okm_offset..okm_offset + to_copy].copy_from_slice(&t[..to_copy]);
        okm_offset += to_copy;
        counter += 1;
        
        crate::utils::zeroize(&mut k_block);
        crate::utils::zeroize(&mut i_key_pad);
        crate::utils::zeroize(&mut o_key_pad);
        crate::utils::zeroize(&mut inner_hash);
    }
    crate::utils::zeroize(&mut t);
}
