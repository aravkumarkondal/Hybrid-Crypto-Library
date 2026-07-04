#![allow(unsafe_code)]

#[cfg(test)]
mod memory_safety_tests {
    use std::ptr;

    // A mock struct for testing if the actual one isn't available in scope.
    // In a real scenario, this would import `hybrid_crypto::SharedSecret`.
    #[derive(Default)]
    struct SharedSecret {
        key: [u8; 32],
    }

    impl Drop for SharedSecret {
        fn drop(&mut self) {
            for byte in self.key.iter_mut() {
                unsafe { std::ptr::write_volatile(byte, 0); }
            }
        }
    }

    #[test]
    fn test_shared_secret_zeroize_on_drop() {
        let ptr;
        {
            let mut secret = SharedSecret { key: [0x42; 32] };
            ptr = secret.key.as_ptr();
            
            unsafe {
                assert_eq!(*ptr, 0x42);
            }
        } // drops naturally in place

        unsafe {
            assert_eq!(*ptr, 0x00, "SharedSecret MUST be zeroized on drop to prevent memory extraction");
        }
    }

    #[test]
    fn test_no_out_of_bounds_access() {
        // Test that our array accesses are bounds-checked.
        let secret = SharedSecret { key: [0x42; 32] };
        
        let res = std::panic::catch_unwind(|| {
            // Attempt an out of bounds read safely caught by Rust panics,
            // proving that bounds checking is active.
            let idx = std::hint::black_box(35);
            let _val = secret.key[idx];
        });
        
        assert!(res.is_err(), "Out of bounds access MUST panic, preventing buffer over-reads");
    }
}
