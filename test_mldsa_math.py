import sys

q = 8380417
zeta = 1753

def bitrev(x, n):
    return int(bin(x)[2:].zfill(n)[::-1], 2)

expected = []
for i in range(256):
    r = pow(zeta, bitrev(i, 8), q)
    # Montgomery representation
    r_mont = (r * (1 << 32)) % q
    expected.append(r_mont)

import re
with open('hybrid_crypto/src/mldsa_zetas.rs', 'r') as f:
    content = f.read()

m = re.search(r'pub const ZETAS: \[i32; 256\] = \[(.*?)\];', content, re.DOTALL)
if m:
    zetas = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
    if zetas == expected:
        print("ML-DSA ZETAS MATCH FIPS 204 (Montgomery)")
    else:
        print("ZETAS DO NOT MATCH!")
        print("First mismatch:", [(i, zetas[i], expected[i]) for i in range(256) if zetas[i] != expected[i]][:5])
EOF
