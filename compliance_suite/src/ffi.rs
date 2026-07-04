
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn prove_ffi_session_init_memory_safety() {
        let payload_len: usize = kani::any();
        kani::assume(payload_len < 512);

        let mut payload = [0u8; 512];
        let ptr = payload.as_mut_ptr();
        let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
        
        let result = unsafe {
            hybrid_session_initialize(&mut handle, ptr, payload_len)
        };

        assert!(result == 0 || result == -1 || result == -2);
    }
}
