#![allow(unsafe_code)]

use crate::*;
use crate::serialization::Serialize;
use core::slice;
use alloc::boxed::Box;

// constants for buffer sizing
pub const E2EE_ECC_PUBLIC_BYTES: usize = 32;
pub const E2EE_ECC_PRIVATE_BYTES: usize = 32;
pub const E2EE_MLDSA87_PUBLIC_BYTES: usize = 2592;
pub const E2EE_MLDSA87_PRIVATE_BYTES: usize = 4896;
pub const E2EE_MLKEM768_PUBLIC_BYTES: usize = 1184;
pub const E2EE_MLKEM768_PRIVATE_BYTES: usize = 2400;
pub const E2EE_MLDSA87_SIGNATURE_BYTES: usize = 4627;

/// Destroys a session and deallocates its memory.
/// # Safety
/// The pointer must be valid and previously allocated by the FFI initiator/responder setups.
#[no_mangle]
pub unsafe extern "C" fn e2ee_session_destroy(session: *mut Session) {
    if !session.is_null() {
        let _ = Box::from_raw(session);
    }
}

/// Generates a long-term Hybrid Identity key pair.
/// # Safety
/// All pointers must be valid and preallocated with correct bounds.
#[no_mangle]
pub unsafe extern "C" fn e2ee_identity_generate(
    entropy_ecc_ptr: *const u8,
    entropy_pqc_ptr: *const u8,
    ecc_priv_out: *mut u8,
    ecc_pub_out: *mut u8,
    pqc_priv_out: *mut u8,
    pqc_pub_out: *mut u8,
    pqc_pub_len_out: *mut usize,
) -> i32 {
    if entropy_ecc_ptr.is_null() || entropy_pqc_ptr.is_null() || ecc_priv_out.is_null() || ecc_pub_out.is_null() || pqc_priv_out.is_null() || pqc_pub_out.is_null() {
        return -1;
    }
    let entropy_ecc = &*(entropy_ecc_ptr as *const [u8; 32]);
    let entropy_pqc = &*(entropy_pqc_ptr as *const [u8; 32]);
    
    let id_key = IdentityKeyPair::generate(entropy_ecc, entropy_pqc);
    
    core::ptr::copy_nonoverlapping(id_key.ecc_private.as_ptr(), ecc_priv_out, 32);
    core::ptr::copy_nonoverlapping(id_key.ecc_public.as_ptr(), ecc_pub_out, 32);
    
    let sk_bytes = id_key.pqc_private.as_slice();
    core::ptr::copy_nonoverlapping(sk_bytes.as_ptr(), pqc_priv_out, sk_bytes.len());
    
    core::ptr::copy_nonoverlapping(id_key.pqc_public.as_ptr(), pqc_pub_out, id_key.pqc_public.len());
    if !pqc_pub_len_out.is_null() {
        *pqc_pub_len_out = id_key.pqc_public.len();
    }
    
    0
}

/// Generates a signed prekey pair and signs it using the long term identity.
/// # Safety
/// All pointers must be valid and preallocated with correct bounds.
#[no_mangle]
pub unsafe extern "C" fn e2ee_signed_prekey_generate(
    id: u32,
    entropy_ecc_ptr: *const u8,
    entropy_pqc_ptr: *const u8,
    identity_ecc_priv_ptr: *const u8,
    identity_pqc_priv_ptr: *const u8,
    identity_pqc_pub_ptr: *const u8,
    sign_rnd_ptr: *const u8,
    ecc_priv_out: *mut u8,
    ecc_pub_out: *mut u8,
    pqc_priv_out: *mut u8,
    pqc_pub_out: *mut u8,
    sig_out: *mut u8,
) -> i32 {
    if entropy_ecc_ptr.is_null() || entropy_pqc_ptr.is_null() || identity_ecc_priv_ptr.is_null() || identity_pqc_priv_ptr.is_null() || identity_pqc_pub_ptr.is_null() || sign_rnd_ptr.is_null() {
        return -1;
    }
    let entropy_ecc = &*(entropy_ecc_ptr as *const [u8; 32]);
    let entropy_pqc = &*(entropy_pqc_ptr as *const [u8; 64]);
    let sign_rnd = &*(sign_rnd_ptr as *const [u8; 32]);

    let mut ecc_priv = [0u8; 32];
    core::ptr::copy_nonoverlapping(identity_ecc_priv_ptr, ecc_priv.as_mut_ptr(), 32);
    let ecc_public = hybrid_crypto::x25519::x25519_base(&ecc_priv);

    let mut pqc_private_vec = alloc::vec![0u8; E2EE_MLDSA87_PRIVATE_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_priv_ptr, pqc_private_vec.as_mut_ptr(), E2EE_MLDSA87_PRIVATE_BYTES);

    let mut pqc_public = alloc::vec![0u8; E2EE_MLDSA87_PUBLIC_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_pub_ptr, pqc_public.as_mut_ptr(), E2EE_MLDSA87_PUBLIC_BYTES);

    let id_key = IdentityKeyPair {
        ecc_private: ecc_priv,
        ecc_public,
        pqc_private: hybrid_crypto::utils::SecretKey(pqc_private_vec),
        pqc_public,
    };

    match SignedPreKeyPair::generate(id, entropy_ecc, entropy_pqc, &id_key, sign_rnd) {
        Ok(spk) => {
            core::ptr::copy_nonoverlapping(spk.ecc_private.as_ptr(), ecc_priv_out, 32);
            core::ptr::copy_nonoverlapping(spk.ecc_public.as_ptr(), ecc_pub_out, 32);
            core::ptr::copy_nonoverlapping(spk.pqc_private.as_ptr(), pqc_priv_out, 2400);
            core::ptr::copy_nonoverlapping(spk.pqc_public.as_ptr(), pqc_pub_out, 1184);
            core::ptr::copy_nonoverlapping(spk.signature.as_ptr(), sig_out, spk.signature.len());
            0
        }
        Err(_) => -1,
    }
}

/// Generates a one-time prekey pair.
/// # Safety
/// All pointers must be valid and preallocated with correct bounds.
#[no_mangle]
pub unsafe extern "C" fn e2ee_onetime_prekey_generate(
    id: u32,
    entropy_ecc_ptr: *const u8,
    entropy_pqc_ptr: *const u8,
    ecc_priv_out: *mut u8,
    ecc_pub_out: *mut u8,
    pqc_priv_out: *mut u8,
    pqc_pub_out: *mut u8,
) -> i32 {
    if entropy_ecc_ptr.is_null() || entropy_pqc_ptr.is_null() || ecc_priv_out.is_null() || ecc_pub_out.is_null() || pqc_priv_out.is_null() || pqc_pub_out.is_null() {
        return -1;
    }
    let entropy_ecc = &*(entropy_ecc_ptr as *const [u8; 32]);
    let entropy_pqc = &*(entropy_pqc_ptr as *const [u8; 64]);

    let opk = OneTimePreKeyPair::generate(id, entropy_ecc, entropy_pqc);
    core::ptr::copy_nonoverlapping(opk.ecc_private.as_ptr(), ecc_priv_out, 32);
    core::ptr::copy_nonoverlapping(opk.ecc_public.as_ptr(), ecc_pub_out, 32);
    core::ptr::copy_nonoverlapping(opk.pqc_private.as_ptr(), pqc_priv_out, 2400);
    core::ptr::copy_nonoverlapping(opk.pqc_public.as_ptr(), pqc_pub_out, 1184);
    0
}

/// Sets up a session as the Initiator and outputs the prekey message and initial message.
/// # Safety
/// Pointers must be valid and point to correct buffers.
#[no_mangle]
pub unsafe extern "C" fn e2ee_session_create_initiator(
    identity_ecc_priv_ptr: *const u8,
    identity_pqc_priv_ptr: *const u8,
    identity_pqc_pub_ptr: *const u8,
    peer_bundle_serialized_ptr: *const u8,
    peer_bundle_serialized_len: usize,
    entropy_ecc_ephem_ptr: *const u8,
    entropy_kem_spk_ptr: *const u8,
    entropy_kem_opk_ptr: *const u8, // Nullable
    ratchet_entropy_dh_ptr: *const u8,
    ratchet_entropy_kem_ptr: *const u8,
    ratchet_entropy_kem_encaps_ptr: *const u8,
    prekey_msg_out: *mut u8,
    prekey_msg_max_len: usize,
    prekey_msg_len_out: *mut usize,
    initial_msg_out: *mut u8,
    initial_msg_max_len: usize,
    initial_msg_len_out: *mut usize,
) -> *mut Session {
    if identity_ecc_priv_ptr.is_null() || identity_pqc_priv_ptr.is_null() || identity_pqc_pub_ptr.is_null() || peer_bundle_serialized_ptr.is_null() || entropy_ecc_ephem_ptr.is_null() || entropy_kem_spk_ptr.is_null() || ratchet_entropy_dh_ptr.is_null() || ratchet_entropy_kem_ptr.is_null() || ratchet_entropy_kem_encaps_ptr.is_null() || prekey_msg_out.is_null() || initial_msg_out.is_null() {
        return core::ptr::null_mut();
    }
    
    let peer_bundle_bytes = slice::from_raw_parts(peer_bundle_serialized_ptr, peer_bundle_serialized_len);
    let peer_bundle = match PreKeyBundle::deserialize(peer_bundle_bytes) {
        Ok(pb) => pb,
        Err(_) => return core::ptr::null_mut(),
    };

    let mut ecc_priv = [0u8; 32];
    core::ptr::copy_nonoverlapping(identity_ecc_priv_ptr, ecc_priv.as_mut_ptr(), 32);
    let ecc_public = hybrid_crypto::x25519::x25519_base(&ecc_priv);

    let mut pqc_private_vec = alloc::vec![0u8; E2EE_MLDSA87_PRIVATE_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_priv_ptr, pqc_private_vec.as_mut_ptr(), E2EE_MLDSA87_PRIVATE_BYTES);

    let mut pqc_public = alloc::vec![0u8; E2EE_MLDSA87_PUBLIC_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_pub_ptr, pqc_public.as_mut_ptr(), E2EE_MLDSA87_PUBLIC_BYTES);

    let my_identity = IdentityKeyPair {
        ecc_private: ecc_priv,
        ecc_public,
        pqc_private: hybrid_crypto::utils::SecretKey(pqc_private_vec),
        pqc_public,
    };

    let entropy_ecc_ephem = &*(entropy_ecc_ephem_ptr as *const [u8; 32]);
    let entropy_kem_spk = &*(entropy_kem_spk_ptr as *const [u8; 32]);
    let entropy_kem_opk = if entropy_kem_opk_ptr.is_null() {
        None
    } else {
        Some(&*(entropy_kem_opk_ptr as *const [u8; 32]))
    };
    
    let ratchet_entropy_dh = &*(ratchet_entropy_dh_ptr as *const [u8; 32]);
    let ratchet_entropy_kem = &*(ratchet_entropy_kem_ptr as *const [u8; 64]);
    let ratchet_entropy_kem_encaps = &*(ratchet_entropy_kem_encaps_ptr as *const [u8; 32]);

    match Session::setup_as_initiator(
        &my_identity,
        &peer_bundle,
        entropy_ecc_ephem,
        entropy_kem_spk,
        entropy_kem_opk,
        ratchet_entropy_dh,
        ratchet_entropy_kem,
        ratchet_entropy_kem_encaps,
    ) {
        Ok((session, prekey_msg, initial_msg)) => {
            let serialized_prekey = prekey_msg.serialize();
            let serialized_initial = initial_msg.serialize();
            
            if serialized_prekey.len() > prekey_msg_max_len || serialized_initial.len() > initial_msg_max_len {
                return core::ptr::null_mut();
            }
            
            core::ptr::copy_nonoverlapping(serialized_prekey.as_ptr(), prekey_msg_out, serialized_prekey.len());
            if !prekey_msg_len_out.is_null() {
                *prekey_msg_len_out = serialized_prekey.len();
            }
            
            core::ptr::copy_nonoverlapping(serialized_initial.as_ptr(), initial_msg_out, serialized_initial.len());
            if !initial_msg_len_out.is_null() {
                *initial_msg_len_out = serialized_initial.len();
            }
            
            Box::into_raw(Box::new(session))
        }
        Err(_) => core::ptr::null_mut(),
    }
}

/// Sets up a session as the Responder upon receiving a PreKeyMessage.
/// # Safety
/// Pointers must be valid and point to correct buffers.
#[no_mangle]
pub unsafe extern "C" fn e2ee_session_create_responder(
    identity_ecc_priv_ptr: *const u8,
    identity_pqc_priv_ptr: *const u8,
    identity_pqc_pub_ptr: *const u8,
    spk_id: u32,
    spk_ecc_priv_ptr: *const u8,
    spk_ecc_pub_ptr: *const u8,
    spk_pqc_priv_ptr: *const u8,
    spk_pqc_pub_ptr: *const u8,
    spk_sig_ptr: *const u8,
    spk_sig_len: usize,
    opk_id: u32,
    opk_ecc_priv_ptr: *const u8, // Nullable
    opk_ecc_pub_ptr: *const u8,  // Nullable
    opk_pqc_priv_ptr: *const u8, // Nullable
    opk_pqc_pub_ptr: *const u8,  // Nullable
    prekey_msg_serialized_ptr: *const u8,
    prekey_msg_serialized_len: usize,
) -> *mut Session {
    if identity_ecc_priv_ptr.is_null() || identity_pqc_priv_ptr.is_null() || identity_pqc_pub_ptr.is_null() || spk_ecc_priv_ptr.is_null() || spk_ecc_pub_ptr.is_null() || spk_pqc_priv_ptr.is_null() || spk_pqc_pub_ptr.is_null() || spk_sig_ptr.is_null() || prekey_msg_serialized_ptr.is_null() {
        return core::ptr::null_mut();
    }

    let prekey_msg_bytes = slice::from_raw_parts(prekey_msg_serialized_ptr, prekey_msg_serialized_len);
    let prekey_msg = match PreKeyMessage::deserialize(prekey_msg_bytes) {
        Ok(pm) => pm,
        Err(_) => return core::ptr::null_mut(),
    };

    let mut ecc_priv = [0u8; 32];
    core::ptr::copy_nonoverlapping(identity_ecc_priv_ptr, ecc_priv.as_mut_ptr(), 32);
    let ecc_public = hybrid_crypto::x25519::x25519_base(&ecc_priv);

    let mut pqc_private_vec = alloc::vec![0u8; E2EE_MLDSA87_PRIVATE_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_priv_ptr, pqc_private_vec.as_mut_ptr(), E2EE_MLDSA87_PRIVATE_BYTES);

    let mut pqc_public = alloc::vec![0u8; E2EE_MLDSA87_PUBLIC_BYTES];
    core::ptr::copy_nonoverlapping(identity_pqc_pub_ptr, pqc_public.as_mut_ptr(), E2EE_MLDSA87_PUBLIC_BYTES);

    let my_identity = IdentityKeyPair {
        ecc_private: ecc_priv,
        ecc_public,
        pqc_private: hybrid_crypto::utils::SecretKey(pqc_private_vec),
        pqc_public,
    };

    let mut spk_ecc_priv = [0u8; 32];
    core::ptr::copy_nonoverlapping(spk_ecc_priv_ptr, spk_ecc_priv.as_mut_ptr(), 32);
    let mut spk_ecc_pub = [0u8; 32];
    core::ptr::copy_nonoverlapping(spk_ecc_pub_ptr, spk_ecc_pub.as_mut_ptr(), 32);
    let mut spk_pqc_priv = [0u8; 2400];
    core::ptr::copy_nonoverlapping(spk_pqc_priv_ptr, spk_pqc_priv.as_mut_ptr(), 2400);
    let mut spk_pqc_pub = [0u8; 1184];
    core::ptr::copy_nonoverlapping(spk_pqc_pub_ptr, spk_pqc_pub.as_mut_ptr(), 1184);
    let spk_sig = slice::from_raw_parts(spk_sig_ptr, spk_sig_len).to_vec();

    let my_spk = SignedPreKeyPair {
        id: spk_id,
        ecc_private: spk_ecc_priv,
        ecc_public: spk_ecc_pub,
        pqc_private: spk_pqc_priv,
        pqc_public: spk_pqc_pub,
        signature: spk_sig,
    };

    let my_opk = if opk_ecc_priv_ptr.is_null() || opk_ecc_pub_ptr.is_null() || opk_pqc_priv_ptr.is_null() || opk_pqc_pub_ptr.is_null() {
        None
    } else {
        let mut opk_ecc_priv = [0u8; 32];
        core::ptr::copy_nonoverlapping(opk_ecc_priv_ptr, opk_ecc_priv.as_mut_ptr(), 32);
        let mut opk_ecc_pub = [0u8; 32];
        core::ptr::copy_nonoverlapping(opk_ecc_pub_ptr, opk_ecc_pub.as_mut_ptr(), 32);
        let mut opk_pqc_priv = [0u8; 2400];
        core::ptr::copy_nonoverlapping(opk_pqc_priv_ptr, opk_pqc_priv.as_mut_ptr(), 2400);
        let mut opk_pqc_pub = [0u8; 1184];
        core::ptr::copy_nonoverlapping(opk_pqc_pub_ptr, opk_pqc_pub.as_mut_ptr(), 1184);

        Some(OneTimePreKeyPair {
            id: opk_id,
            ecc_private: opk_ecc_priv,
            ecc_public: opk_ecc_pub,
            pqc_private: opk_pqc_priv,
            pqc_public: opk_pqc_pub,
        })
    };

    match Session::setup_as_responder(&my_identity, &my_spk, my_opk.as_ref(), &prekey_msg) {
        Ok(session) => Box::into_raw(Box::new(session)),
        Err(_) => core::ptr::null_mut(),
    }
}

/// Encrypts a plaintext message and writes its serialized representation.
/// # Safety
/// Pointers must be valid and point to correct buffers.
#[no_mangle]
pub unsafe extern "C" fn e2ee_session_encrypt(
    session: *mut Session,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_max_len: usize,
    ciphertext_len_out: *mut usize,
) -> i32 {
    if session.is_null() || ciphertext_out.is_null() || (plaintext_len > 0 && plaintext_ptr.is_null()) {
        return -1;
    }
    let session = &mut *session;
    let plaintext = slice::from_raw_parts(plaintext_ptr, plaintext_len);
    
    match session.encrypt_message(plaintext) {
        Ok(msg) => {
            let serialized = msg.serialize();
            if serialized.len() > ciphertext_max_len {
                return -1;
            }
            core::ptr::copy_nonoverlapping(serialized.as_ptr(), ciphertext_out, serialized.len());
            if !ciphertext_len_out.is_null() {
                *ciphertext_len_out = serialized.len();
            }
            0
        }
        Err(_) => -1,
    }
}

/// Decrypts a serialized message and writes the plaintext.
/// # Safety
/// Pointers must be valid and point to correct buffers.
#[no_mangle]
pub unsafe extern "C" fn e2ee_session_decrypt(
    session: *mut Session,
    msg_serialized_ptr: *const u8,
    msg_serialized_len: usize,
    my_new_dh_entropy_ptr: *const u8,
    my_new_kem_entropy_ptr: *const u8,
    my_new_kem_encaps_entropy_ptr: *const u8,
    plaintext_out: *mut u8,
    plaintext_max_len: usize,
    plaintext_len_out: *mut usize,
) -> i32 {
    if session.is_null() || msg_serialized_ptr.is_null() || my_new_dh_entropy_ptr.is_null() || my_new_kem_entropy_ptr.is_null() || my_new_kem_encaps_entropy_ptr.is_null() || (plaintext_max_len > 0 && plaintext_out.is_null()) {
        return -1;
    }
    let session = &mut *session;
    
    let msg_bytes = slice::from_raw_parts(msg_serialized_ptr, msg_serialized_len);
    let msg = match Message::deserialize(msg_bytes) {
        Ok(m) => m,
        Err(_) => return -1,
    };
    
    let my_new_dh_entropy = &*(my_new_dh_entropy_ptr as *const [u8; 32]);
    let my_new_kem_entropy = &*(my_new_kem_entropy_ptr as *const [u8; 64]);
    let my_new_kem_encaps_entropy = &*(my_new_kem_encaps_entropy_ptr as *const [u8; 32]);

    match session.decrypt_message(&msg, my_new_dh_entropy, my_new_kem_entropy, my_new_kem_encaps_entropy) {
        Ok(plaintext) => {
            if plaintext.len() > plaintext_max_len {
                return -1;
            }
            core::ptr::copy_nonoverlapping(plaintext.as_ptr(), plaintext_out, plaintext.len());
            if !plaintext_len_out.is_null() {
                *plaintext_len_out = plaintext.len();
            }
            0
        }
        Err(_) => -1,
    }
}
