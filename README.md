# Hybrid Cryptography & E2EE Library (Post-Quantum Fortified)

This repository is a production-hardened Rust workspace implementing state-of-the-art hybrid post-quantum cryptography (PQC) and End-to-End Encryption (E2EE) protocols. It is designed for maximum memory safety, side-channel immunity, and hardware tamper resistance.

---

## Repository Architecture

This workspace is modularized to ensure structural separation between cryptographic primitives, hardware acceleration layers, and FFI/WASM APIs:

```
├── compliance_suite/ # Cross-crate integration, standards validation, and FFI tests
├── cpu/              # SIMD (AVX2/AVX512/Neon) hardware acceleration & CPU stress tests
├── e2ee/             # Double Ratchet, X3DH, Sender Keys, and serialization logic
├── gpu/              # OpenCL/WGSL hardware acceleration and driver error trapping
├── hybrid_crypto/    # Core primitives: ML-KEM-768, ML-DSA-87, X25519, AES-GCM-256
└── wasm_api/         # WebAssembly bindings (JS interop) for headless browser environments
```

---

## 🔒 Security Hardening

To satisfy production-grade cryptographic criteria, the following compiler and code-level defenses are enforced:

1. **Memory Zeroization**: Crucial keys, sessions, and intermediate values (`Session`, `IdentityKey`, `SharedSecret`) implement a custom `Drop` layer using `std::ptr::write_volatile`. This prevents the compiler from optimizing out memory clearing, ensuring secrets are physically wiped from RAM immediately after going out of scope.
2. **Global Linting (`unsafe_code = "deny"`)**: Enforced globally at the workspace level. The usage of `unsafe` is strictly forbidden in all higher-level crates, isolating raw memory manipulation solely to SIMD, OpenCL wrappers, and FFI borders.
3. **No-Branch Side-Channel Resistance**: Primitive algorithms (like `ml_dsa_87_verify`) execute branching evaluations over flattened boolean flags in constant time, preventing execution timing variance leaks.
4. **Binary Hardening Profiles (`Cargo.toml`)**:
   - `opt-level = 3` (Maximum compiler optimization passes)
   - `lto = "fat"` (Global Link-Time Optimization to eliminate dead code and reduce execution surface area)
   - `codegen-units = 1` (Enhances optimization cohesion)
   - `panic = "unwind"` (Retains dynamic panic recovery paths)

---

## 🧪 Testing Matrices

This codebase enforces the strict rule: **"Code that is not tested is assumed broken"**. We achieve this via six testing dimensions:

1. **Unit & Integration Tests**: Executed per-crate via `cargo test --workspace`.
2. **Property-Based Testing (`proptest`)**: Generates millions of randomized inputs to assert invariants (e.g., `deserialize(serialize(x)) == x`).
3. **Fuzzing (`cargo fuzz`)**: Feeds random byte arrays directly into ML-KEM decapsulation and E2EE state parsing engines to test crash resilience.
4. **Symbolic Memory Auditing (`Miri`)**: Verifies memory behavior using `run_miri.sh` to guarantee the complete absence of undefined behavior (UB) and memory leaks.
5. **Formal Verification (`Kani`)**: Uses Bounded Model Checking to mathematically prove that the FFI endpoints never overflow or crash under any arbitrary pointer range.
6. **WASM V8 Runtime Tests**: Runs `wasm-pack test --node` in a headless NodeJS V8 engine to confirm compatibility across JS-WASM boundaries.

---

## 🛠️ Developer Commands (Agent & Human Reference)

### Build & Lint
```bash
cargo build --release
cargo clippy --workspace --all-targets
```

### Run Tests
```bash
# Standard tests
cargo test --workspace

# Property tests specifically
cargo test --package hybrid_crypto --test proptests
cargo test --package e2ee --test proptests

# WASM NodeJS boundary verification
cd wasm_api && wasm-pack test --node
```

### Run Memory Safety Audits
```bash
# Run Rust's symbolic executor (expects Miri installed)
./run_miri.sh
```

---

## 📦 Sharing the Library Securely (Private Git Sharing)

If you need to share this library with collaborators **without making it public** or adding them directly to your personal GitHub organization, use these secure methods:

### Method 1: Git Bundle (Direct Offline Sharing)
You can package the entire repository history (including commits, branches, and tags) into a single, highly compressed binary file and share it via a secure file-transfer mechanism (e.g., encrypted cloud storage, Signal, SFTP).

**To create the bundle:**
```bash
git bundle create hybrid_crypto_lib.bundle master
```

**To clone the repository from the bundle:**
```bash
git clone hybrid_crypto_lib.bundle -b master hybrid_crypto_workspace
```

### Method 2: Private Cargo Git Dependency
Collaborators can import this library directly into their own Rust projects via Cargo by referencing your private repository URL.

They will need to authenticate using a **GitHub Personal Access Token (PAT)** or an **SSH Key** configured in their environment:

```toml
[dependencies]
hybrid_crypto = { git = "https://github.com/aravkumarkondal/Hybrid-Crypto-Library.git", branch = "master" }
e2ee = { git = "https://github.com/aravkumarkondal/Hybrid-Crypto-Library.git", branch = "master" }
```
**Authentication Setup:**
1. **HTTPS with Token**: The collaborator generates a Github PAT with `repo` scope and configures Git credentials:
   ```bash
   git config --global credential.helper store
   ```
2. **SSH Key**: The collaborator adds their public SSH key to their Github account, and cargo resolves the dependency securely:
   ```toml
   hybrid_crypto = { git = "git@github.com:aravkumarkondal/Hybrid-Crypto-Library.git", branch = "master" }
   ```
