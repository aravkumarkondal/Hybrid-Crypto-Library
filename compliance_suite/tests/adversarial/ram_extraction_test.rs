#[cfg(test)]
mod ram_extraction_attacks {
    use hybrid_crypto::utils::SecretKey;
    
    // Simulating a Cold-Boot RAM Extraction Attack / Heartbleed Heap Scavenging
    #[test]
    fn test_ram_cold_boot_extraction_defense() {
        // We create a highly sensitive piece of data on the heap (like a private key).
        let secret_bytes = vec![0xABu8; 64];
        let secret_key = SecretKey(secret_bytes);
        
        // We use raw pointers to simulate an attacker looking at the exact heap address
        let heap_ptr: *const u8 = secret_key.0.as_ptr();
        
        // Let's verify the memory actually contains our secret before it is dropped
        unsafe {
            assert_eq!(*heap_ptr, 0xAB, "Sanity check: Heap memory should hold the secret");
        }
        
        // Trigger the explicit drop (which calls our Zeroize implementation)
        drop(secret_key);
        
        // NOW, we simulate the attacker scraping the RAM at that same physical heap address.
        // If our zeroize defense works, the physical memory MUST be overwritten with zeros,
        // defeating the cold-boot extraction!
        // NOTE: Accessing memory after drop is technically Undefined Behavior in Rust,
        // but this is exactly what an attacker does from outside the process or via a bug.
        // We do a raw read here in testing to mathematically prove the memory was zeroed.
        unsafe {
            // The memory should be 0x00 if zeroize worked correctly before the OS reclaimed it.
            // (Assuming the OS hasn't instantly unmapped the page, which it usually doesn't for small allocs).
            assert_eq!(*heap_ptr, 0x00, "RAM EXTRACTION FAILED! Private key was not zeroized in physical memory upon drop!");
        }
    }
}
