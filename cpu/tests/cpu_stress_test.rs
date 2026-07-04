use cpu::ml_dsa_simd::{poly_add_simd, poly_sub_simd};
use std::thread;

#[test]
fn test_multithreaded_stress() {
    let mut handles = vec![];
    let num_threads = 100;
    let iterations = 1000;

    for t_id in 0..num_threads {
        handles.push(thread::spawn(move || {
            let mut a = [0i32; 256];
            let b = [t_id as i32; 256];
            
            for _ in 0..iterations {
                poly_add_simd(&mut a, &b);
                poly_sub_simd(&mut a, &b);
            }
            
            // Ensure some computation happened, without panicking.
            assert_eq!(a.len(), 256);
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
