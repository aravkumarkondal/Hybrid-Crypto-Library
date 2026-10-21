# Hybrid Cryptography & E2EE Library (Post-Quantum Fortified)

This repository is a production-hardened Rust workspace implementing state-of-the-art hybrid post-quantum cryptography (PQC) and End-to-End Encryption (E2EE) protocols. It is designed for maximum memory safety, speed, modularity, side-channel immunity, and hardware tamper resistance.

---

## 🔒 Cryptographic Algorithms (The `hybrid_crypto` Crate)

The core cryptography is abstracted behind a modular `CryptoProvider` interface, meaning algorithms can be swapped entirely if necessary. By default, it operates with a Zero-Dependency, `no_std` compliant software backend:

1. **Key Encapsulation (KEM)**: `ML-KEM-768` (FIPS 203). Post-Quantum secure key encapsulation.
2. **Digital Signatures**: `ML-DSA-87` (FIPS 204). Post-Quantum secure digital signatures.
3. **Elliptic Curve Cryptography**: `X25519`. Classical ECDH key agreement.
4. **Symmetric Encryption**: `AES-256-GCM`. Authenticated bulk payload encryption.
5. **Key Derivation (KDF)**: `HKDF-SHA256`. 
6. **Hardware Acceleration**: 
   - `cpu` crate: SIMD AVX2/NEON intrinsics for rapid polynomial multiplication.
   - `gpu` crate: OpenCL/WGSL kernels for offloaded matrix transformations.

---

## 🛡️ E2EE Protocol Features (The `e2ee` Crate)

The E2EE module is heavily optimized for zero-copy memory operations and compile-time state safety (`RatchetState` validation).

1. **X3DH (Extended Triple Diffie-Hellman)**: Initiates secure sessions anonymously. Uses a hybrid approach combining X25519 and ML-KEM to establish initial shared secrets that are secure against quantum computers.
2. **The Double Ratchet**: Implements the Signal-style Double Ratchet algorithm using HKDF chains. It provides Forward Secrecy (FS) and Post-Compromise Security (PCS). Limits are strictly enforced to prevent DoS (e.g., maximum skipped key buffers).
3. **TreeKEM (Continuous Group Key Agreement)**: Implements a Left-Balanced Binary Tree (LBBT) protocol based on RFC 9420 (MLS) to facilitate highly efficient, asynchronous multi-member group chats.
4. **Sender Keys**: Highly scalable multicast encryption for large groups.
5. **Transparency Logs (Merkle Trees)**: Provides public cryptographic proof of inclusion, preventing server tampering or ghost-user injection.
6. **FS-Log (Forward Secret Logging)**: Tamper-proof, cryptographically signed audit logs that roll forward invisibly.
7. **QR Reassembly**: Support for visual verification codes and splitting payloads across visual mediums.
8. **Hardware Keystore Abstractions**: Pluggable integrations for all major platforms ensuring Post-Quantum keys are strictly sealed out-of-band:
   - macOS / iOS: Apple Keychain Integration (`apple_keystore`).
   - Windows: Credential Manager DPAPI (`windows_keystore`).
   - Linux: Secret Service DBus (`linux_keystore`).

---

## 🚀 How to Use the Library

The `splendid-mendeleev` workspace is completely abstracted. You can initialize a Post-Quantum E2E chat session in just a few lines of code.

### 1. Generating Identities
```rust
use e2ee::identity::IdentityKeyPair;
use hybrid_crypto::provider::StandardCryptoProvider;

// 1. Generate an Identity KeyPair (hybrid X25519 + ML-DSA)
let entropy = [0u8; 64]; // In production, use OsRng
let alice_identity = IdentityKeyPair::generate(&entropy);
```

### 2. Establishing a Session (X3DH)
```rust
use e2ee::x3dh::X3DH;
use e2ee::prekeys::{PreKeyBundle, SignedPreKey, OneTimePreKey};

// Alice generates a PreKey Bundle to publish to a server
let spk = SignedPreKey::generate(&alice_identity, 1, &entropy);
let opk = OneTimePreKey::generate(1, &entropy);
let bundle = PreKeyBundle::new(alice_identity.public_key(), spk, Some(opk));

// Bob uses Alice's bundle to initiate a session
let (bob_session, initial_message) = X3DH::initiate(&bundle, &bob_identity, &entropy).unwrap();
```

### 3. Encrypting & Decrypting (Double Ratchet)
```rust
use e2ee::messages::Payload;

// Bob encrypts a message
let msg = b"Hello Post-Quantum World!";
let ciphertext = bob_session.encrypt_message(msg).unwrap();

// Alice receives the initial message, builds her session, and decrypts
let mut alice_session = X3DH::receive(&initial_message, &alice_identity, &spk_private, Some(&opk_private)).unwrap();

let plaintext = alice_session.decrypt_message(&ciphertext).unwrap();
assert_eq!(plaintext, msg);
```

---

## 🔒 Security Hardening

To satisfy production-grade cryptographic criteria, the following compiler and code-level defenses are enforced:

1. **Memory Zeroization**: Crucial keys, sessions, and intermediate values implement a custom `Drop` layer using `std::ptr::write_volatile`. This ensures secrets are physically wiped from RAM immediately after going out of scope.
2. **Global Linting (`unsafe_code = "deny"`)**: Enforced globally at the workspace level. The usage of `unsafe` is strictly forbidden in all higher-level crates.
3. **No-Branch Side-Channel Resistance**: Primitive algorithms (like `ml_dsa_87_verify`) execute branching evaluations over flattened boolean flags in constant time, preventing execution timing variance leaks.
4. **Type-Safe States**: Internal Double Ratchet mechanisms mathematically enforce `is_ready` barriers at compile-time to prevent uninitialized payload encryption.

---

## 🛠️ Developer Commands

### Build & Lint
```bash
cargo build --release
cargo clippy --workspace --all-targets
```

### Run Tests
```bash
# Standard tests (Single Threaded to prevent Memory Spikes)
cargo test --workspace -- --test-threads=1

# WASM NodeJS boundary verification
cd wasm_api && wasm-pack test --node
```
