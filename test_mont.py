import numpy as np

Q = 8380417

def fqmul_avx2(a, b):
    qinv = np.int32(-58728449)
    
    a_low = np.int32(a) * np.int32(b)
    u = np.int32(a_low) * qinv
    
    a_even = np.int64(a) * np.int64(b)
    u_even = np.int64(u) * np.int64(Q)
    
    sum_even = a_even + u_even
    
    # logical shift right by 32
    res_even = np.uint64(sum_even) >> np.uint64(32)
    res_even = np.int32(res_even)
    
    if res_even < 0:
        res_even += Q
    return res_even

for a in [1, 2, Q-1, Q]:
    b = 1
    R_inv = pow(1<<32, -1, Q)
    expected = (a * b * R_inv) % Q
    print(f"a={a}, b={b}, expected={expected}, got={fqmul_avx2(a,b)}")

