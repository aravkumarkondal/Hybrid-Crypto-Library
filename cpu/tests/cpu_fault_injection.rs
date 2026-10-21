#![allow(unsafe_code)]
use cpu::ml_dsa_simd::poly_add_simd;
use std::thread;
use std::sync::atomic::{AtomicI32, Ordering};

struct SharedMem(usize);

unsafe impl Send for SharedMem {}
unsafe impl Sync for SharedMem {}

// Dummy signature verification that expects unmodified data
fn verify_signature(data: &[AtomicI32; 256]) -> bool {
    let mut sum = 0i32;
    for val in data {
        sum = sum.wrapping_add(val.load(Ordering::Relaxed));
    }
    // Expected sum if unmodified would be 256 (array of 1s)
    sum == 256
}

#[test]
fn test_rowhammer_simulation() {
    // Initialize an array of AtomicI32 with 1s
    let mut data = Box::new(std::array::from_fn::<AtomicI32, 256, _>(|_| AtomicI32::new(1)));
    let ptr = data.as_mut_ptr() as usize;
    let shared_mem = SharedMem(ptr);
    let shared_mem2 = SharedMem(ptr);

    let rowhammer_thread = thread::spawn(move || {
        let p = shared_mem.0 as *const AtomicI32;
        for _ in 0..10_000 {
            for i in 0..256 {
                unsafe {
                    let atom = &*p.add(i);
                    let val = atom.load(Ordering::Relaxed);
                    // Corrupt data to simulate hardware fault
                    atom.store(val ^ 0x01010101, Ordering::Relaxed);
                }
            }
        }
    });

    let compute_thread = thread::spawn(move || {
        let p = shared_mem2.0 as *const [AtomicI32; 256];
        let mut a = [0i32; 256];
        let mut verification_failed = false;

        for _ in 0..1000 {
            let b_ref = unsafe { &*p };
            
            // Extract the integers safely
            let mut extracted = [0i32; 256];
            for i in 0..256 {
                extracted[i] = b_ref[i].load(Ordering::Relaxed);
            }
            
            poly_add_simd(&mut a, &extracted);
            
            // Check if corruption occurred and verification failed safely
            if !verify_signature(b_ref) {
                verification_failed = true;
            }
        }
        
        // Assert that we gracefully detected the fault (i.e. didn't crash)
        // and that verification failures were correctly observed.
        assert!(verification_failed, "Should have experienced and detected data corruption");
        a
    });

    rowhammer_thread.join().unwrap();
    let _ = compute_thread.join().unwrap();
}
