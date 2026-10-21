# REGISTER OF KNOWN LIMITATIONS & THREAT BOUNDARIES

This register documents structural, platform, physical, and theoretical limitations inherent to the repository architecture, algorithms, and dependencies. In accordance with zero-trust engineering principles, **no limitation may be suppressed, hidden, or downgraded**.

---

## 1. Hardware Backed Storage: Envelope Sealing vs. True On-Chip Execution

- **Limitation**: Commercial hardware security modules (Apple T2/A17 Secure Enclaves, Windows TPM 2.0 chips, Linux HSMs, and browser WebCrypto) natively support classical cryptography (ECDSA, RSA, AES, SHA), but **do NOT natively support Post-Quantum lattice cryptography (ML-DSA-87, ML-KEM-768)**.
- **Implementation Reality**: The platform keystores (`apple_software_keystore`, `windows_software_keystore`, `linux_software_keystore`, `web_keystore`) implement **AES-256-GCM envelope encryption**:
  1. The Key Encryption Key (KEK) is stored in the OS Keychain / Credential Manager / TPM / WebCrypto.
  2. The 4928-byte ML-DSA and ECC identity private key blob is sealed at rest.
  3. When `sign_payload` or `shared_secret` is executed, the private key blob is **unsealed into host process RAM**, the cryptographic operation is computed in software, and the unsealed key is zeroized on drop.
- **Security Impact**: Keys do NOT remain strictly within hardware boundaries during execution. An adversary with kernel root privileges, hypervisor compromise, or physical bus snooping can capture keys while they are resident in RAM.
- **Classification**: **INTRINSIC PLATFORM CONSTRAINT** (unresolvable until hardware vendors release PQC-native HSMs).

---

## 2. Cold-Boot & Physical Memory Dumping Risks

- **Limitation**: While all intermediate private keys, stack buffers, NTT polynomial coefficients, and AES-GCM keystreams utilize `ZeroizingArray`, `SecretKey`, and `volatile` memory scrubbing with `compiler_fence` barriers, DRAM capacitance allows memory retention for seconds to minutes if subjected to rapid cooling (liquid nitrogen / cold-boot attack).
- **Security Impact**: An attacker with immediate physical access to DRAM chips following a signing operation could theoretically extract remnant private key material from unrefreshed capacitor states.
- **Mitigation Status**: Software cannot prevent physical capacitor leakage; hardware-level memory encryption (e.g. AMD SME, Intel TME) is required at the OS/hardware layer.

---

## 3. Formal Verification & Kani Proof Coverage

- **Limitation**: Formal verification using `kani` is currently scoped to discrete mathematical routines in `compliance_suite/tests/kani_proofs.rs`. The SIMD vector extensions in `cpu` and OpenCL/WGSL kernels in `gpu` have **not** been subjected to end-to-end formal theorem proving.
- **Security Impact**: Mathematical correctness is substantiated by extensive test vectors, randomized property tests (`proptest`), and fuzzing, but absolute absence of arithmetic overflow or subtle edge-case bounds panics cannot be mathematically proven across every possible input permutation.
- **Classification**: **ROADMAP WORK ITEM** (requires modern Kani toolchain upgrade and comprehensive harness authoring).

---

## 4. WebAssembly & Browser Memory Lifecycle

- **Limitation**: When compiled to `wasm32-unknown-unknown` and executed within browser JavaScript engines (V8, JavaScriptCore, SpiderMonkey):
  1. WebCrypto keys stored in IndexedDB are subject to browser sandbox security.
  2. The browser's garbage collector manages `ArrayBuffer` allocations. While the Rust WebAssembly linear memory (`wasm-memory`) can be explicitly zeroized, memory copied into JavaScript typed arrays (`Uint8Array`) by `web-sys` or `js-sys` is cleared via `.fill(0)` in JavaScript, but true physical memory overwriting depends on browser VM internals.
- **Security Impact**: Key material may linger in browser process heap allocations until garbage collection cycles complete.
- **Classification**: **INTRINSIC WASM / JAVASCRIPT ARCHITECTURAL LIMITATION**.

---

## 5. WebAssembly SIMD Performance Constraints

- **Limitation**: AVX2, AVX-512, and ARM NEON hardware acceleration modules are explicitly compiled out in `wasm32-unknown-unknown` targets. All NTT transformations and modular reductions revert to scalar fallbacks.
- **Impact**: Cryptographic operations in web browsers execute approximately $3\times$ to $6\times$ slower than native desktop/mobile binaries.
- **Classification**: **PORTABILITY TRADEOFF**.

---

## 6. Distributed Scalability & Infrastructure Scope

- **Limitation**: The repository is strictly a **client-side cryptographic library and E2EE state engine**. It does NOT contain distributed backend message routers, database storage sharding, push notification relays, or consensus servers.
- **Impact**: While a single client node can scale to thousands of active sessions in memory, claiming support for "hundreds of thousands" or "millions" of simultaneous users across an enterprise requires external distributed server infrastructure that is outside the scope of this repository.
- **Classification**: **SCOPE BOUNDARY**.

---

## 7. Container Serialization Keying

- **Limitation**: The parameterless `Serialize` trait implementation on `MultiDeviceSession` (`e2ee/src/session.rs`) uses a default fixed KEK for internal container bundling because the trait signature `fn serialize(&self) -> Vec<u8>` does not accept runtime key parameters.
- **Impact**: Callers must NOT rely on parameterless `MultiDeviceSession::serialize` for at-rest confidentiality. Callers must either use `export_state_with_key(&master_key)` or encapsulate the container within `SessionBackup::create(&session, &backup_key, &iv)`.
- **Classification**: **API DESIGN CONSTRAINT**.
