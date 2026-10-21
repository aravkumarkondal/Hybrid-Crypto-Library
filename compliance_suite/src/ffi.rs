use e2ee::{Session, SessionState, serialization::Serialize};
use std::ffi::c_void;

#[no_mangle]
pub unsafe extern "C" fn hybrid_session_initialize(
    out_handle: *mut *mut c_void,
    payload_ptr: *const u8,
    payload_len: usize,
) -> i32 {
    if out_handle.is_null() || payload_ptr.is_null() {
        return -1;
    }
    
    let payload = std::slice::from_raw_parts(payload_ptr, payload_len);
    
    let master_key = [0x00; 32];
    match Session::restore_state(payload, &master_key) {
        Ok(session) => {
            let session_box = Box::new(session);
            *out_handle = Box::into_raw(session_box) as *mut c_void;
            0
        }
        Err(_) => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn hybrid_session_destroy(handle: *mut c_void) {
    if !handle.is_null() {
        let _ = Box::from_raw(handle as *mut Session);
    }
}

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
