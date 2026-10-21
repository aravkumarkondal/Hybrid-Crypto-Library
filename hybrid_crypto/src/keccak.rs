#![allow(unsafe_code)]

#![allow(dead_code)]

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

pub fn keccak_f1600(a: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta
        let mut c = [0u64; 5];
        let mut d = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }

        // Rho and Pi
        let mut x = 1;
        let mut y = 0;
        let mut current = a[1];
        for t in 0..24 {
            let next_x = y;
            let next_y = (2 * x + 3 * y) % 5;
            let next = a[next_x + 5 * next_y];
            a[next_x + 5 * next_y] = current.rotate_left(((t + 1) * (t + 2) / 2) % 64);
            current = next;
            x = next_x;
            y = next_y;
        }

        // Chi
        for y in 0..5 {
            let mut temp = [0u64; 5];
            for x in 0..5 {
                temp[x] = a[x + 5 * y];
            }
            for x in 0..5 {
                a[x + 5 * y] = temp[x] ^ (!temp[(x + 1) % 5] & temp[(x + 2) % 5]);
            }
        }

// Iota
        a[0] ^= RC[round];
    }
}

#[derive(Clone)]
pub struct KeccakState {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    domain: u8,
}

impl KeccakState {
    pub fn new(rate_bytes: usize, domain: u8) -> Self {
        Self {
            state: [0; 25],
            rate: rate_bytes,
            pos: 0,
            domain,
        }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let take = core::cmp::min(self.rate - self.pos, data.len() - i);
            for j in 0..take {
                let byte_idx = self.pos + j;
                let word_idx = byte_idx / 8;
                let shift = (byte_idx % 8) * 8;
                self.state[word_idx] ^= (data[i + j] as u64) << shift;
            }
            self.pos += take;
            i += take;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub fn finalize(&mut self) {
        let byte_idx = self.pos;
        let word_idx = byte_idx / 8;
        let shift = (byte_idx % 8) * 8;
        self.state[word_idx] ^= (self.domain as u64) << shift;

        let last_word_idx = (self.rate - 1) / 8;
        let last_shift = ((self.rate - 1) % 8) * 8;
        self.state[last_word_idx] ^= 1u64 << (last_shift + 7);

        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let take = core::cmp::min(self.rate - self.pos, out.len() - i);
            for j in 0..take {
                let byte_idx = self.pos + j;
                let word_idx = byte_idx / 8;
                let shift = (byte_idx % 8) * 8;
                out[i + j] = (self.state[word_idx] >> shift) as u8;
            }
            self.pos += take;
            i += take;
        }
    }
}

impl Drop for KeccakState {
    fn drop(&mut self) {
        crate::utils::zeroize(unsafe {
            core::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, 200)
        });
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut state = KeccakState::new(136, 0x06); // rate = 1088 bits = 136 bytes
    state.absorb(data);
    state.finalize();
    let mut out = [0u8; 32];
    state.squeeze(&mut out);
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut state = KeccakState::new(72, 0x06); // rate = 576 bits = 72 bytes
    state.absorb(data);
    state.finalize();
    let mut out = [0u8; 64];
    state.squeeze(&mut out);
    out
}

pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut state = KeccakState::new(168, 0x1f); // rate = 1344 bits = 168 bytes
    state.absorb(data);
    state.finalize();
    state.squeeze(out);
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut state = KeccakState::new(136, 0x1f); // rate = 1088 bits = 136 bytes
    state.absorb(data);
    state.finalize();
    state.squeeze(out);
}

pub struct Shake128Xof {
    state: KeccakState,
}

impl Shake128Xof {
    pub fn new(data: &[u8]) -> Self {
        let mut state = KeccakState::new(168, 0x1f);
        state.absorb(data);
        state.finalize();
        Self { state }
    }
    
    pub fn squeeze_bytes(&mut self, out: &mut [u8]) {
        self.state.squeeze(out);
    }
}

pub struct Shake256Xof {
    state: KeccakState,
}

impl Shake256Xof {
    pub fn new(data: &[u8]) -> Self {
        let mut state = KeccakState::new(136, 0x1f);
        state.absorb(data);
        state.finalize();
        Self { state }
    }
    
    pub fn squeeze_bytes(&mut self, out: &mut [u8]) {
        self.state.squeeze(out);
    }
}

// ==========================================
// FIPS 203 Specific Primitives (Section 4.1)
// ==========================================

pub fn h(data: &[u8]) -> [u8; 32] {
    sha3_256(data)
}

pub fn g(data: &[u8]) -> [u8; 64] {
    sha3_512(data)
}

pub fn j(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(data, &mut out);
    out
}


pub fn prf_eta2(s: &[u8; 32], b: u8) -> [u8; 128] {
    let mut data = [0u8; 33];
    data[..32].copy_from_slice(s);
    data[32] = b;
    let mut out = [0u8; 128]; // 64 * eta for eta=2
    shake256(&data, &mut out);
    out
}

pub fn prf_eta3(s: &[u8; 32], b: u8) -> [u8; 192] {
    let mut data = [0u8; 33];
    data[..32].copy_from_slice(s);
    data[32] = b;
    let mut out = [0u8; 192]; // 64 * eta for eta=3
    shake256(&data, &mut out);
    out
}

pub fn xof(rho: &[u8; 32], i: u8, j: u8) -> Shake128Xof {
    let mut data = [0u8; 34];
    data[..32].copy_from_slice(rho);
    data[32] = i;
    data[33] = j;
    Shake128Xof::new(&data)
}

