#![allow(unsafe_code)]
extern crate alloc;

#[cfg(test)]
mod e2ee_memory_safety_tests {
    
    use e2ee::identity::SoftwareIdentityKeyPair;
    
    
    

    use hybrid_crypto::utils::ZeroizingArray;

    #[test]
    fn test_zeroizing_array_on_drop() {
        let ptr;
        {
            let mut secret = ZeroizingArray::new([0xAA; 32]);
            ptr = secret.as_mut_ptr();
            unsafe {
                assert_eq!(*ptr, 0xAA);
            }
        } // drops naturally in place

        unsafe {
            assert_eq!(*ptr, 0x00, "ZeroizingArray must be zeroized on drop");
        }
    }

    #[test]
    fn test_software_identity_zeroize_on_drop() {
        let ecc_ptr;
        {
            let mut sw_key = SoftwareIdentityKeyPair::generate(&[0xBB; 32], &[0xBB; 32]);
            ecc_ptr = sw_key.ecc_private.as_mut_ptr();
            unsafe {
                assert_eq!(*ecc_ptr, 0xBB);
            }
        }

        unsafe {
            assert_eq!(*ecc_ptr, 0x00, "SoftwareIdentityKeyPair ecc_private must be zeroized on drop");
        }
    }
}
