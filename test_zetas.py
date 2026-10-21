import sys

q = 3329
zeta = 17

def bitrev(x, n):
    return int(bin(x)[2:].zfill(n)[::-1], 2)

expected = []
for i in range(128):
    # FIPS 203 Kyber zetas are zeta^(bitrev(i, 7)) ?
    expected.append(pow(zeta, bitrev(i, 7), q))

# Let's read the ZETAS array from ml_kem.rs
import re
with open('hybrid_crypto/src/ml_kem.rs', 'r') as f:
    content = f.read()

m = re.search(r'const ZETAS: \[i16; 128\] = \[(.*?)\];', content, re.DOTALL)
if m:
    zetas = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
    if zetas == expected:
        print("ZETAS MATCH FIPS 203 (bit-reversed)")
    else:
        print("ZETAS DO NOT MATCH!")
        print("First mismatch:", [(i, zetas[i], expected[i]) for i in range(128) if zetas[i] != expected[i]][:5])
