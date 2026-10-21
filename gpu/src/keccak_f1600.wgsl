// WebGPU Compute Shader for Keccak-f[1600] Permutation
// Useful for accelerating massive parallel hashes (e.g., Matrix A generation in ML-DSA)

struct State {
    // Note: This 200-byte state array is intentionally kept thread-local (register/local memory).
    // While moving it to `var<workgroup>` could theoretically reduce register pressure,
    // it introduces significant risk of bank conflicts and barrier synchronization deadlocks
    // during the massive parallel matrix permutations (e.g. ML-DSA Matrix A).
    a: array<vec2<u32>, 25> // 64-bit state represented as two 32-bit uints for WGSL compatibility
};

@group(0) @binding(0) var<storage, read_write> states: array<State>;

fn rotl64(x: vec2<u32>, shift: u32) -> vec2<u32> {
    if shift == 0u { return x; }
    if shift == 32u { return vec2<u32>(x.y, x.x); }
    if shift < 32u {
        let low = (x.x << shift) | (x.y >> (32u - shift));
        let high = (x.y << shift) | (x.x >> (32u - shift));
        return vec2<u32>(low, high);
    }
    let shift_adj = shift - 32u;
    let low = (x.y << shift_adj) | (x.x >> (32u - shift_adj));
    let high = (x.x << shift_adj) | (x.y >> (32u - shift_adj));
    return vec2<u32>(low, high);
}


const RC = array<vec2<u32>, 24>(
    vec2<u32>(0x00000001u, 0x00000000u), vec2<u32>(0x00008082u, 0x00000000u),
    vec2<u32>(0x0000808au, 0x80000000u), vec2<u32>(0x80008000u, 0x80000000u),
    vec2<u32>(0x0000808bu, 0x00000000u), vec2<u32>(0x80000001u, 0x00000000u),
    vec2<u32>(0x80008081u, 0x80000000u), vec2<u32>(0x00008009u, 0x80000000u),
    vec2<u32>(0x0000008au, 0x00000000u), vec2<u32>(0x00000088u, 0x00000000u),
    vec2<u32>(0x80008009u, 0x00000000u), vec2<u32>(0x8000000au, 0x00000000u),
    vec2<u32>(0x8000808bu, 0x00000000u), vec2<u32>(0x0000008bu, 0x80000000u),
    vec2<u32>(0x00008089u, 0x80000000u), vec2<u32>(0x00008003u, 0x80000000u),
    vec2<u32>(0x00008002u, 0x80000000u), vec2<u32>(0x00000080u, 0x80000000u),
    vec2<u32>(0x0000800au, 0x00000000u), vec2<u32>(0x8000000au, 0x80000000u),
    vec2<u32>(0x80008081u, 0x80000000u), vec2<u32>(0x00008080u, 0x80000000u),
    vec2<u32>(0x80000001u, 0x00000000u), vec2<u32>(0x80008008u, 0x80000000u)
);

@compute @workgroup_size(64)
fn keccak_f1600(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    let num_states = arrayLength(&states);
    if idx >= num_states { return; }

    var state = states[idx].a;
    
    for (var round = 0u; round < 24u; round++) {
        // Theta
        var c: array<vec2<u32>, 5>;
        for (var i = 0u; i < 5u; i++) {
            c[i] = state[i] ^ state[i+5u] ^ state[i+10u] ^ state[i+15u] ^ state[i+20u];
        }
        var d: array<vec2<u32>, 5>;
        for (var i = 0u; i < 5u; i++) {
            d[i] = c[(i + 4u) % 5u] ^ rotl64(c[(i + 1u) % 5u], 1u);
        }
        for (var i = 0u; i < 5u; i++) {
            for (var j = 0u; j < 5u; j++) {
                state[i + j*5u] ^= d[i];
            }
        }
        
        // Rho and Pi
        var x = 1u;
        var y = 0u;
        var current = state[1u];
        for (var t = 0u; t < 24u; t++) {
            let next_x = y;
            let next_y = (2u * x + 3u * y) % 5u;
            let next = state[next_x + 5u * next_y];
            
            let shift = ((t + 1u) * (t + 2u) / 2u) % 64u;
            state[next_x + 5u * next_y] = rotl64(current, shift);
            
            current = next;
            x = next_x;
            y = next_y;
        }
        
        // Chi
        for (var j = 0u; j < 5u; j++) {
            var temp: array<vec2<u32>, 5>;
            for (var i = 0u; i < 5u; i++) {
                temp[i] = state[i + 5u * j];
            }
            for (var i = 0u; i < 5u; i++) {
                let not_next = vec2<u32>(~temp[(i + 1u) % 5u].x, ~temp[(i + 1u) % 5u].y);
                let and_expr = vec2<u32>(not_next.x & temp[(i + 2u) % 5u].x, not_next.y & temp[(i + 2u) % 5u].y);
                state[i + 5u * j] = vec2<u32>(temp[i].x ^ and_expr.x, temp[i].y ^ and_expr.y);
            }
        }
        
        // Iota
        state[0] = vec2<u32>(state[0].x ^ RC[round].x, state[0].y ^ RC[round].y);
    }
    
    states[idx].a = state;
}
