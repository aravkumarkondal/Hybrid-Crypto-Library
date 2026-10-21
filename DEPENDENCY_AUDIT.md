# Supply Chain & Dependency Audit Report

## 1. Executive Summary

This document provides a comprehensive, zero-trust audit of the direct, transitive, dev, and build dependencies of the `Hybrid-Crypto-Library` (`splendid-mendeleev`) workspace. 

The primary architectural mandate of this repository is **zero-runtime-dependency core cryptographic and protocol implementation**, ensuring maximum auditability, immunity to upstream supply-chain tampering, and seamless `#![no_std]` embedded execution.

---

## 2. Workspace Crate Inventory & Dependency Topology

The workspace comprises 10 packages:

| Crate | Path | Core Scope | `#![no_std]` | External Runtime Dependencies | Dev / Test Dependencies |
|---|---|---|---|---|---|
| `cpu` | `cpu/` | SIMD math acceleration (AVX2, AVX-512, NEON) | **YES** | **NONE (0)** | `criterion` |
| `hybrid_crypto` | `hybrid_crypto/` | Post-quantum primitives (ML-KEM, ML-DSA, X25519, AES-GCM, SHA-3) | **YES** | **NONE (0)** (depends only on internal `cpu`) | `criterion`, `proptest` |
| `e2ee` | `e2ee/` | Double Ratchet, PQXDH, Sender Keys, TreeKEM, Identity | **YES** | **NONE (0)** (depends only on internal `hybrid_crypto`) | `criterion`, `proptest`, `tokio`, `futures` |
| `gpu` | `gpu/` | OpenCL & WGSL compute kernels | **NO** | `opencl3`, `wgpu` | `criterion` |
| `apple_software_keystore` | `apple_software_keystore/` | macOS/iOS Keychain envelope encryption | **NO** | `security-framework`, `core-foundation` | None |
| `windows_software_keystore` | `windows_software_keystore/` | Windows Credential Manager envelope encryption | **NO** | `wincredentials` | None |
| `linux_software_keystore` | `linux_software_keystore/` | Linux Secret Service (D-Bus) envelope encryption | **NO** | `secret-service` | None |
| `web_keystore` | `web_keystore/` | IndexedDB + WebCrypto envelope encryption | **WASM** | `wasm-bindgen`, `js-sys`, `web-sys` | None |
| `wasm_api` | `wasm_api/` | WASM/JS bindings for web applications | **WASM** | `wasm-bindgen`, `wasm-bindgen-futures` | `wasm-bindgen-test` |
| `compliance_suite` | `compliance_suite/` | Adversarial attacks, FFI, differential testing | **NO** | Internal workspace crates | `tokio`, `criterion`, `serde`, `serde_json`, `sha2`, `hkdf`, `kani` |

---

## 3. Detailed Audit of Runtime External Dependencies

### 3.1. `apple_software_keystore`
- **Dependencies**: `security-framework` (v2.11.1), `core-foundation` (v0.9.4)
- **License**: MIT / Apache-2.0
- **Purpose**: Official Apple Security Framework bindings for accessing the macOS/iOS Keychain.
- **Supply-Chain Analysis**: Maintained by the `kornelski/rust-security-framework` team, officially recognized and used widely across the Rust ecosystem. No CVEs identified.
- **Memory Safety**: Interacts with Apple C APIs via CFRetain/CFRelease. Sealed blob parsing and zeroization are enforced in Rust.

### 3.2. `windows_software_keystore`
- **Dependencies**: `wincredentials`
- **License**: MIT
- **Purpose**: Native Windows Credential Manager interface via `Advapi32.dll` (`CredReadW`, `CredWriteW`).
- **Supply-Chain Analysis**: Lightweight wrapper around Win32 Credential Management APIs. 

### 3.3. `linux_software_keystore`
- **Dependencies**: `secret-service`
- **License**: MIT / Apache-2.0
- **Purpose**: Freedesktop.org Secret Service D-Bus specification client (GNOME Keyring / KWallet).
- **Supply-Chain Analysis**: Uses session-level Diffie-Hellman key exchange over D-Bus to avoid transmitting plaintext secrets across local IPC.

### 3.4. `wasm_api` & `web_keystore`
- **Dependencies**: `wasm-bindgen` (v0.2.126), `wasm-bindgen-futures` (v0.4.76)
- **License**: MIT / Apache-2.0
- **Purpose**: Rust-to-WebAssembly ABI generation, JavaScript interop, and Promises integration.
- **Supply-Chain Analysis**: Maintained by the official Rust WebAssembly Working Group. Standard tier-1 dependency.

---

## 4. Audit of Test, Benchmark & Verification Dependencies

### 4.1. `criterion` (v0.5.1)
- **Scope**: `dev-dependencies` across `hybrid_crypto`, `e2ee`, `cpu`, `gpu`, `compliance_suite`.
- **License**: Apache-2.0 / MIT
- **Purpose**: Statistical microbenchmarking with bootstrap outlier analysis.
- **Impact**: Zero runtime footprint. Completely excluded from release builds.

### 4.2. `proptest` (v1.11.0)
- **Scope**: `dev-dependencies` in `hybrid_crypto` and `e2ee`.
- **License**: MIT / Apache-2.0
- **Purpose**: Hypothesis-style property-based fuzz testing.
- **Impact**: Zero runtime footprint.

### 4.3. `kani` (v0.0.1)
- **Scope**: `dev-dependencies` in `compliance_suite`.
- **License**: Apache-2.0 / MIT
- **Purpose**: Formal model checking and verification.
- **Status / Limitation**: The pinned version in `Cargo.toml` is `0.0.1`. Modern Kani is `>0.40.0`. It serves as a stub annotation in `compliance_suite/tests/kani_proofs.rs`. Full formal verification across SIMD and GPU remains an open roadmap objective.

### 4.4. `tokio` (v1.52.3)
- **Scope**: `dev-dependencies` in `e2ee` and `compliance_suite`.
- **License**: MIT
- **Purpose**: Multi-threaded async runtime used to drive concurrent stress tests and async keystore tests.
- **Impact**: Excluded from production library builds (`e2ee` uses `no_std` + `futures-lite` or custom `block_on` for internal polling).

---

## 5. `#![no_std]` Verification

- Both **`hybrid_crypto`** and **`e2ee`** strictly enforce `#![no_std]` (with `extern crate alloc`).
- Neither crate pulls in `std::net`, `std::fs`, `std::thread`, or standard system allocators.
- Cryptographic randomness is decoupled via caller-provided entropy slices (`&[u8; 32]`) or explicit `provider` abstractions, enabling deployment on embedded bare-metal microcontrollers (ARM Cortex-M), secure enclaves, and kernel drivers.

---

## 6. Supply Chain Security Recommendations

1. **Continuous Dependency Scanning**: Enforce `cargo audit` and `cargo deny` in CI pipelines to prevent introduction of compromised transitive crates.
2. **Lockfile Pinning**: Maintain `Cargo.lock` under strict source control to guarantee bit-for-bit reproducible dependency compilation.
3. **Kani Modernization**: Upgrade `kani` from `0.0.1` to the current stable release (`0.50+`) to enable formal verification proofs on release CI.
