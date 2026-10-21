use hybrid_crypto::{HybridKeyPair, hybrid_encrypt_payload, hybrid_decrypt_payload};
use std::time::Instant;

fn main() {
    let paragraph = "\
Cryptography is the practice and study of techniques for secure communication in the presence \
of adversarial behavior. More generally, cryptography is about constructing and analyzing protocols \
that prevent third parties or the public from reading private messages. Modern cryptography exists \
at the intersection of the disciplines of mathematics, computer science, electrical engineering, \
communication science, and physics. Applications of cryptography include electronic commerce, \
chip-based payment cards, digital currencies, computer passwords, and military communications. \
In recent years, the advent of quantum computing has introduced a new paradigm of threats to \
traditional public-key cryptography. Algorithms like RSA and Elliptic Curve Cryptography rely on \
the computational difficulty of factoring large integers and computing discrete logarithms. \
Shor's algorithm, running on a sufficiently powerful quantum computer, can solve these problems \
in polynomial time, effectively breaking widespread encryption standards. To mitigate this looming \
threat, the cryptographic community, led by organizations such as NIST, has been actively developing \
Post-Quantum Cryptography (PQC). These new algorithms are based on mathematical problems that are \
believed to be intractable for both classical and quantum computers, such as learning with errors \
over lattices, hash-based signatures, and multivariate quadratic equations. The transition to PQC \
is critical to ensuring long-term data confidentiality and integrity. Hybrid cryptosystems combine \
the proven security of classical algorithms like X25519 with the quantum resistance of ML-KEM to \
provide robust defense-in-depth during this transitional period, ensuring data remains secure even \
if one of the underlying mathematical problems is eventually solved.";

    println!("============================================================");
    println!("Hybrid Encryption Process Demonstration");
    println!("============================================================");
    println!("\n[1] Original Paragraph ({} words, {} bytes):", paragraph.split_whitespace().count(), paragraph.len());
    println!("{}\n", paragraph);

    // 1. Generate keys
    println!("[2] Generating receiver's Hybrid KeyPair (X25519 + ML-KEM-768)...");
    let start = Instant::now();
    let entropy_ecc = [10u8; 32]; // In production, use a secure RNG
    let entropy_pqc = [20u8; 64];
    let receiver_keypair = HybridKeyPair::generate(&entropy_ecc, &entropy_pqc);
    println!("    Keys generated in {:?}", start.elapsed());

    // 2. Encrypt
    println!("\n[3] Encrypting the paragraph...");
    let start = Instant::now();
    let entropy_ecc_ephem = [30u8; 32];
    let entropy_pqc_encaps = [40u8; 32];
    let iv = [0x55u8; 12];
    
    let package = hybrid_encrypt_payload(
        paragraph.as_bytes(),
        &receiver_keypair.ecc_public,
        &receiver_keypair.pqc_public,
        &entropy_ecc_ephem,
        &entropy_pqc_encaps,
        &iv,
    ).expect("Encryption failed");
    println!("    Encryption completed in {:?}", start.elapsed());
    println!("    -> Ciphertext length: {} bytes", package.ciphertext.len());
    println!("    -> AES-GCM Tag: {:02x?}", package.tag);
    println!("    -> KEM Ciphertext length: {} bytes", package.pqc_ciphertext.len());
    
    // 3. Decrypt
    println!("\n[4] Decrypting the package using receiver's private keys...");
    let start = Instant::now();
    let decrypted_bytes = hybrid_decrypt_payload(
        &package.ciphertext,
        &package.iv,
        &package.tag,
        &package.ecc_ephemeral_pub,
        &package.pqc_ciphertext,
        &receiver_keypair.ecc_private,
        &receiver_keypair.pqc_private,
    ).expect("Decryption failed");
    println!("    Decryption completed in {:?}", start.elapsed());

    let decrypted_text = String::from_utf8(decrypted_bytes.0.clone()).expect("Invalid UTF-8");
    
    println!("\n[5] Decrypted Paragraph:");
    println!("{}\n", decrypted_text);
    
    if decrypted_text == paragraph {
        println!("============================================================");
        println!("✅ SUCCESS: The decrypted paragraph matches the original perfectly!");
        println!("============================================================");
    } else {
        println!("❌ ERROR: The decrypted paragraph does not match!");
    }
}
