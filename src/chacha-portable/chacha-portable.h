#ifndef CHACHA_PORTABLE_H 
#define CHACHA_PORTABLE_H

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_KEY_SIZE (32)
#define CHACHA20_NONCE_SIZE (12)

// xor data with a ChaCha20 keystream as per RFC8439
void chacha20_xor_stream(
        void *dest, 
        const void *source, 
        size_t length,
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
);

#endif
