#ifndef COMPACT_8439_H
#define COMPACT_8439_H
/*
 This library implements RFC 8439 a.k.a. ChaCha20-Poly1305 AEAD

 You should use this library to avoid attackers mutating or reusing your
 encrypted messages.
*/
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define RFC_8439_MAC_SIZE (16)
#define RFC_8439_KEY_SIZE (32)
#define RFC_8439_NONCE_SIZE (12)

void portable_chacha20_poly1305_encrypt(
    uint8_t mac[RFC_8439_MAC_SIZE],
    uint8_t *cipher_text,
    const uint8_t key[RFC_8439_KEY_SIZE],
    const uint8_t nonce[RFC_8439_NONCE_SIZE],
    const uint8_t *ad, // can be NULL for no Additional Data
    size_t ad_size,  
    const uint8_t *plain_text,
    size_t plain_text_size
);

bool portable_chacha20_poly1305_decrypt(
    uint8_t *plain_text,
    const uint8_t key[RFC_8439_KEY_SIZE],
    const uint8_t nonce[RFC_8439_NONCE_SIZE],
    const uint8_t *ad, // can be NULL for no Additional Data
    size_t ad_size,  
    const uint8_t mac[RFC_8439_MAC_SIZE],
    const uint8_t *cipher_text,
    size_t cipher_text_size
);

#endif
