use wasm_api::WasmIdentityKeyPair;

#[test]
fn test_wasm_entropy_zeroization() {
    let mut entropy_ecc = [0x5A; 32];
    let mut entropy_pqc = [0xA5; 32];
    
    let _ = WasmIdentityKeyPair::new(&mut entropy_ecc, &mut entropy_pqc);
    
    assert_eq!(entropy_ecc, [0u8; 32]);
    assert_eq!(entropy_pqc, [0u8; 32]);
}
