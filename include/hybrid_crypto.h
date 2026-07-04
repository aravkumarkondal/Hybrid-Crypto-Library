#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * ML-DSA-87 Constants
 */
#define MLDSA87_PUBLIC_KEY_BYTES 2592
#define MLDSA87_PRIVATE_KEY_BYTES 4896
#define MLDSA87_SIGNATURE_BYTES 4627

/*
 * Hybrid Encryption Constants
 */
#define HYBRID_ECC_PUB_BYTES 32
#define HYBRID_ECC_PRIV_BYTES 32
#define HYBRID_PQC_PUB_BYTES 1184
#define HYBRID_PQC_PRIV_BYTES 2400
#define HYBRID_PQC_CIPHERTEXT_BYTES 1088

/*
 * ---------------------------------------
 * ML-DSA-87 Signatures
 * ---------------------------------------
 */

/**
 * Generate a new ML-DSA-87 keypair.
 * entropy_ptr: 32 bytes of high-quality randomness
 */
int mldsa87_generate_keypair(
    const uint8_t *entropy_ptr,
    uint8_t *pub_key_out,
    size_t pub_key_len,
    uint8_t *priv_key_out,
    size_t priv_key_len
);

/**
 * Sign a message using ML-DSA-87.
 * rnd_ptr: 32 bytes of randomness
 */
int mldsa87_sign(
    const uint8_t *msg_ptr,
    size_t msg_len,
    const uint8_t *ctx_ptr,
    size_t ctx_len,
    const uint8_t *rnd_ptr,
    const uint8_t *priv_key_ptr,
    uint8_t *sig_out,
    size_t sig_out_len
);

/**
 * Verify an ML-DSA-87 signature.
 * Returns: 1 if signature is valid, 0 otherwise
 */
int mldsa87_verify(
    const uint8_t *msg_ptr,
    size_t msg_len,
    const uint8_t *ctx_ptr,
    size_t ctx_len,
    const uint8_t *sig_ptr,
    const uint8_t *pub_key_ptr
);

/*
 * ---------------------------------------
 * Hybrid Encapsulation & Encryption
 * ---------------------------------------
 */

int hybrid_generate_keypair(
    const uint8_t *entropy_ecc_ptr, /* 32 bytes */
    const uint8_t *entropy_pqc_ptr, /* 64 bytes */
    uint8_t *ecc_priv_out,
    size_t ecc_priv_len,
    uint8_t *ecc_pub_out,
    size_t ecc_pub_len,
    uint8_t *pqc_priv_out,
    size_t pqc_priv_len,
    uint8_t *pqc_pub_out,
    size_t pqc_pub_len
);

int hybrid_encrypt(
    const uint8_t *payload_ptr,
    size_t payload_len,
    const uint8_t *ecc_pub_ptr,
    const uint8_t *pqc_pub_ptr,
    const uint8_t *entropy_ecc_ptr, /* 32 bytes */
    const uint8_t *entropy_pqc_ptr, /* 32 bytes */
    const uint8_t *iv_ptr,          /* 12 bytes */
    uint8_t *ciphertext_out,
    uint8_t *iv_out,
    uint8_t *tag_out,
    uint8_t *ecc_ephem_out,
    uint8_t *pqc_cipher_out,
    size_t ciphertext_out_len
);

int hybrid_decrypt(
    const uint8_t *ciphertext_ptr,
    size_t ciphertext_len,
    const uint8_t *iv_ptr,
    const uint8_t *tag_ptr,
    const uint8_t *ecc_ephem_ptr,
    const uint8_t *pqc_cipher_ptr,
    const uint8_t *ecc_priv_ptr,
    const uint8_t *pqc_priv_ptr,
    uint8_t *output_ptr,
    size_t output_len
);

#ifdef __cplusplus
}
#endif

#endif // HYBRID_CRYPTO_H
