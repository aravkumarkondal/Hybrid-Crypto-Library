#![allow(unsafe_code)]

#![allow(dead_code)]

/// Safely overwrite memory with zeros.
/// This prevents sensitive data (like keys) from lingering in memory.
/// Uses `core::ptr::write_volatile` to bypass compiler Dead-Store Elimination (DSE) passes.
#[inline(never)]
pub fn zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Dummy volatile read to defeat advanced LLVM DSE
    for byte in data.iter() {
        unsafe {
            let _ = core::ptr::read_volatile(byte);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    speculation_barrier();
}

/// Safely overwrite a 32-bit word with zeros.
/// Uses `core::ptr::write_volatile` to bypass compiler Dead-Store Elimination (DSE) passes.
#[inline(never)]
pub fn zeroize_u32(data: &mut u32) {
    unsafe {
        core::ptr::write_volatile(data, 0);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    unsafe {
        let _ = core::ptr::read_volatile(data);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Safely overwrite an i32 slice with zeros.
#[inline(never)]
pub fn zeroize_i32(data: &mut [i32]) {
    for val in data.iter_mut() {
        unsafe { core::ptr::write_volatile(val, 0); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    for val in data.iter() {
        unsafe { let _ = core::ptr::read_volatile(val); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Safely overwrite a u64 slice with zeros.
#[inline(never)]
pub fn zeroize_u64(data: &mut [u64]) {
    for val in data.iter_mut() {
        unsafe { core::ptr::write_volatile(val, 0); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    for val in data.iter() {
        unsafe { let _ = core::ptr::read_volatile(val); }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Hardware-level Speculation Barrier.
///
/// On x86/x86_64: Emits `LFENCE`, which serializes instruction dispatch and halts
/// speculative out-of-order execution across the barrier (Spectre v1/v2 mitigation).
///
/// On AArch64 (ARM64): Emits `csdb` (Consumption of Speculative Data Barrier)
/// to prevent speculative execution across data-dependent boundaries.
///
/// On other architectures: Enforces a sequentially consistent compiler fence.
#[inline(always)]
pub fn speculation_barrier() {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_arch = "wasm32")))]
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::x86_64::_mm_lfence();
        #[cfg(target_arch = "x86")]
        core::arch::x86::_mm_lfence();
    }
    #[cfg(all(target_arch = "aarch64", not(target_arch = "wasm32")))]
    unsafe {
        core::arch::asm!("csdb", options(nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Speculative Load Hardening & Bounds Sanitization.
///
/// Ensures that even under speculative branch misprediction (Spectre-v1 / CVE-2017-5753),
/// out-of-bounds indices are masked to zero and cannot speculatively read out-of-bounds
/// memory or pollute cache lines observable by SMT/HyperThreading siblings.
#[inline(always)]
pub fn speculative_sanitize_index(idx: usize, len: usize) -> usize {
    let is_in_bounds = (idx < len) as usize;
    let mask = 0usize.wrapping_sub(is_in_bounds);
    speculation_barrier();
    idx & mask
}

/// Speculation-hardened, constant-time table lookup.
///
/// Sequentially accesses EVERY byte in the table, accumulating the target value
/// using constant-time bitwise selection. Because EVERY cache line in the table
/// is unconditionally loaded, no secret-dependent cache lines are loaded or evicted,
/// fully neutralizing Prime+Probe, Flush+Reload, and speculative cache-timing attacks.
pub fn speculative_ct_lookup_u8(table: &[u8], secret_idx: usize) -> u8 {
    let mut result = 0u8;
    let safe_idx = speculative_sanitize_index(secret_idx, table.len());
    for (i, &val) in table.iter().enumerate() {
        let matches = (i == safe_idx) as u8;
        result = ct_select_u8(result, val, matches);
    }
    speculation_barrier();
    result
}

/// Constant-time memory comparison.
/// Returns true if `a` and `b` have the same contents, false otherwise.
/// The time taken only depends on the lengths, not the contents.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    unsafe {
        result = core::ptr::read_volatile(&result);
    }
    speculation_barrier();
    result == 0
}

/// Constant-time conditional swap.
/// If `swap_flag` is 1, `a` and `b` are swapped. If `swap_flag` is 0, they are not.
/// `swap_flag` must be 0 or 1.
pub fn cswap(swap_flag: u64, a: &mut [u64], b: &mut [u64]) {
    speculation_barrier();
    let mask = 0u64.wrapping_sub(swap_flag); // All 1s if swap_flag is 1, else all 0s
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let mut dummy = mask & (*x ^ *y);
        unsafe {
            dummy = core::ptr::read_volatile(&dummy);
        }
        *x ^= dummy;
        *y ^= dummy;
    }
    speculation_barrier();
}

/// Constant-time conditional copy.
/// If `copy_flag` is 1, `src` is copied to `dest`. If 0, `dest` is unchanged.
/// `copy_flag` must be 0 or 1.
pub fn ccopy(copy_flag: u8, dest: &mut [u8], src: &[u8]) {
    speculation_barrier();
    let mask = 0u8.wrapping_sub(copy_flag);
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        let mut dummy = mask & (*d ^ *s);
        unsafe { dummy = core::ptr::read_volatile(&dummy); }
        *d ^= dummy;
    }
    speculation_barrier();
}

/// Constant-time conditional select for u8.
/// Returns `b` if `choice == 1`, or `a` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u8(a: u8, b: u8, choice: u8) -> u8 {
    let mask = 0u8.wrapping_sub(choice);
    let mut dummy = mask & (a ^ b);
    unsafe { dummy = core::ptr::read_volatile(&dummy); }
    a ^ dummy
}

/// Constant-time conditional select for u32.
/// Returns `b` if `choice == 1`, or `a` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u32(a: u32, b: u32, choice: u32) -> u32 {
    let mask = 0u32.wrapping_sub(choice);
    let mut dummy = mask & (a ^ b);
    unsafe { dummy = core::ptr::read_volatile(&dummy); }
    a ^ dummy
}

/// Constant-time conditional select for u64.
/// Returns `b` if `choice == 1`, or `a` if `choice == 0`.
#[inline(always)]
pub fn ct_select_u64(a: u64, b: u64, choice: u8) -> u64 {
    let mask = 0u64.wrapping_sub(choice as u64);
    let mut dummy = mask & (a ^ b);
    unsafe { dummy = core::ptr::read_volatile(&dummy); }
    a ^ dummy
}

use core::ops::{Deref, DerefMut};

/// A wrapper that zeroizes the underlying array when it goes out of scope.
pub struct ZeroizingArray<const N: usize>(pub [u8; N]);

impl<const N: usize> ZeroizingArray<N> {
    pub fn new(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> Drop for ZeroizingArray<N> {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

impl<const N: usize> Deref for ZeroizingArray<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ZeroizingArray<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

use alloc::vec::Vec;

/// A wrapper for dynamically allocated secrets that zeroizes on drop.
pub struct SecretKey(pub Vec<u8>);

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretKey(<REDACTED>)")
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        crate::utils::constant_time_eq(&self.0, &other.0)
    }
}
impl Eq for SecretKey {}

impl PartialEq<&[u8]> for SecretKey {
    fn eq(&self, other: &&[u8]) -> bool {
        crate::utils::constant_time_eq(&self.0, other)
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for SecretKey {
    fn eq(&self, other: &&[u8; N]) -> bool {
        crate::utils::constant_time_eq(&self.0, *other)
    }
}

impl PartialEq<[u8]> for SecretKey {
    fn eq(&self, other: &[u8]) -> bool {
        crate::utils::constant_time_eq(&self.0, other)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        let cap = self.0.capacity();
        let ptr = self.0.as_mut_ptr();
        unsafe {
            for i in 0..cap {
                core::ptr::write_volatile(ptr.add(i), 0);
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            for i in 0..cap {
                let _ = core::ptr::read_volatile(ptr.add(i));
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            self.0.set_len(0);
        }
    }
}

impl Deref for SecretKey {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
