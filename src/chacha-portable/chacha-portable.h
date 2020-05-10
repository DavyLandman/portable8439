#ifndef CHACHA_PORTABLE_H
#define CHACHA_PORTABLE_H

#if !defined(__cplusplus) && \
    !defined(_MSC_VER) && \
    (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#    error "C99 or newer required"
#endif

#include <stddef.h>
#include <stdint.h>

#if CHAR_BIT > 8
#    error "Systems without native octals not supported"
#endif

#define CHACHA20_KEY_SIZE (32)
#define CHACHA20_NONCE_SIZE (12)

#if defined(_MSC_VER) || defined(__cplusplus) 
// add restrict support
#    if (defined(_MSC_VER) && _MSC_VER >= 1900) || defined(__clang__) || defined(__GNUC__)
#       define restrict __restrict
#    else
#       define restrict
#    endif
#endif

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
