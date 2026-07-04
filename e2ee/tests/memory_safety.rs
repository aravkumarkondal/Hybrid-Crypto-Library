#![allow(unsafe_code)]

#[cfg(test)]
mod e2ee_memory_safety_tests {
    use std::ptr;

    macro_rules! define_secret_struct {
        ($name:ident, $size:expr) => {
            struct $name {
                data: [u8; $size],
            }

            impl $name {
                fn new() -> Self {
                    Self { data: [0x55; $size] }
                }
            }

            impl Drop for $name {
                fn drop(&mut self) {
                    for byte in self.data.iter_mut() {
                        unsafe { std::ptr::write_volatile(byte, 0); }
                    }
                }
            }
        };
    }

    define_secret_struct!(Session, 64);
    define_secret_struct!(SenderKey, 32);
    define_secret_struct!(IdentityKey, 32);
    define_secret_struct!(Ratchet, 128);

    macro_rules! test_zeroize_on_drop {
        ($test_name:ident, $struct_name:ident) => {
            #[test]
            fn $test_name() {
                let ptr;
                {
                    let mut secret = $struct_name::new();
                    ptr = secret.data.as_ptr();
                    unsafe {
                        assert_eq!(*ptr, 0x55);
                    }
                } // drops naturally in place

                unsafe {
                    assert_eq!(*ptr, 0x00, stringify!($struct_name must be zeroized on drop));
                }
            }
        };
    }

    test_zeroize_on_drop!(test_session_zeroize, Session);
    test_zeroize_on_drop!(test_sender_key_zeroize, SenderKey);
    test_zeroize_on_drop!(test_identity_key_zeroize, IdentityKey);
    test_zeroize_on_drop!(test_ratchet_zeroize, Ratchet);

    #[test]
    fn test_use_after_free_prevention() {
        let ptr;
        {
            let mut key = SenderKey::new();
            ptr = key.data.as_mut_ptr();
        }
        
        unsafe {
            assert_eq!(*ptr, 0x00, "UAF read must yield zeroized data, preventing secret extraction");
        }
    }
}
