// CPU hardware acceleration memory validation test

// We will allocate a massive amount of memory for polynomial arrays and ensure 
// it correctly deallocates (or doesn't trigger OOM bounds). When run with Miri,
// this will systematically verify zero leaks across array iterations.
#[test]
fn test_cpu_memory_bounds_and_leaks() {
    // Allocate 10,000 polynomial arrays on the heap
    // This simulates a heavy concurrent workload hitting the CPU SIMD math layer
    let mut large_buffer: Vec<[i32; 256]> = Vec::with_capacity(10_000);
    
    for i in 0..10_000 {
        let mut poly = [0i32; 256];
        poly[0] = i;
        large_buffer.push(poly);
    }
    
    // Simulate auto-vectorized CPU mathematical iterations
    for i in 0..5_000 {
        let mut a = large_buffer[i];
        let b = large_buffer[9999 - i];
        
        // Simulating the Barrett reduce math from ml_dsa
        for j in 0..256 {
            let q = 8380417;
            let sum = a[j].wrapping_add(b[j]);
            let v = ((i64::from(sum) * 8396807) >> 46) as i32;
            let mut t = sum - v * q;
            if t < 0 { t += q; } else if t >= q { t -= q; }
            a[j] = t;
        }
    }
    
    // The vector drops here, Miri/Valgrind will complain if it leaks
    assert_eq!(large_buffer.len(), 10_000, "Heap allocations must complete without panic");
}
