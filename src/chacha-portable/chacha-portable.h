#ifndef CHACHA_PORTABLE_H 
#define CHACHA_PORTABLE_H

#include <stddef.h>
#include <stdint.h>

#if CHAR_BIT > 8
#    error "Systems without native octals not suppoted"
#endif

#define CHACHA20_KEY_SIZE (32)
#define CHACHA20_NONCE_SIZE (12)

// xor data with a ChaCha20 keystream as per RFC8439
void chacha20_xor_stream(
        uint8_t *restrict dest, 
        const uint8_t *restrict source, 
        size_t length,
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
);

void rfc8439_keygen(
        uint8_t poly_key[32],
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE]
);

#endif
