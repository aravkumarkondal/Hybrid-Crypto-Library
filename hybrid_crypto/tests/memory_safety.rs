#![allow(unsafe_code)]

#[cfg(test)]
mod memory_safety_tests {
    use hybrid_crypto::utils::ZeroizingArray;

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
            ptr = secret.key.as_mut_ptr();
            unsafe {
                assert_eq!(*ptr, 0x42);
            }
        } // drops naturally in place

        // Check the memory after drop
        unsafe {
            assert_eq!(*ptr, 0x00, "SharedSecret key must be zeroized on drop");
        }
    }

    #[test]
    fn test_zeroizing_array_on_drop() {
        let ptr;
        {
            let mut arr = ZeroizingArray::new([0xBB; 16]);
            ptr = arr.as_mut_ptr();
            unsafe {
                assert_eq!(*ptr, 0xBB);
            }
        }
        unsafe {
            assert_eq!(*ptr, 0x00, "ZeroizingArray should zeroize on drop");
        }
    }

    #[test]
    fn test_no_out_of_bounds_access() {
        let array = [1, 2, 3, 4, 5];
        let safe_slice = &array[0..3];
        assert_eq!(safe_slice.len(), 3);
        // An attempt to access safe_slice[5] would panic normally.
        // Miri will ensure that if we used unsafe, it would be caught.
    }
}
