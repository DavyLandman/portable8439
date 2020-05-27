#include "chacha-portable.h"
#include <string.h>
#include <assert.h>

// this is a fresh implementation of chacha20, based on the description in rfc8349
// it's such a nice compact algorithm that it is easy to do.
// In relationship to other c implementation this implementation:
//  - pure c99
//  - big & little endian support
//  - safe for architectures that don't support unaligned reads
//
// Next to this, we try to be fast as possible without resorting inline assembly. 

// based on https://sourceforge.net/p/predef/wiki/Endianness/
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
        __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#   define __HAVE_LITTLE_ENDIAN 1
#elif defined(__LITTLE_ENDIAN__) || \
        defined(__ARMEL__) || \
        defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || \
        defined(_MIPSEL) || \
        defined(__MIPSEL) || \
        defined(__MIPSEL__) || \
        defined(__XTENSA_EL__) || \
        defined(__AVR__) || \
        defined(LITTLE_ENDIAN)
#   define __HAVE_LITTLE_ENDIAN 1
#endif

#ifndef TEST_SLOW_PATH
#   if defined(__HAVE_LITTLE_ENDIAN)
#       define FAST_PATH
#   endif
#endif


#define CHACHA20_STATE_WORDS (16)
#define CHACHA20_BLOCK_SIZE (CHACHA20_STATE_WORDS * sizeof(uint32_t))


#ifdef FAST_PATH
#define store_32_le(target, source) \
    memcpy(&(target), source, sizeof(uint32_t))
#else
#define store_32_le(target, source) \
    target \
        =  (uint32_t)(source)[0] \
        | ((uint32_t)(source)[1]) << 8 \
        | ((uint32_t)(source)[2]) << 16 \
        | ((uint32_t)(source)[3]) << 24
#endif



static void initialize_state(
        uint32_t state[CHACHA20_STATE_WORDS], 
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
) {
#ifdef static_assert 
    static_assert(sizeof(uint32_t) == 4, "We don't support systems that do not conform to standard of uint32_t being exact 32bit wide");
#endif
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    store_32_le(state[4], key);
    store_32_le(state[5], key + 4);
    store_32_le(state[6], key + 8);
    store_32_le(state[7], key + 12);
    store_32_le(state[8], key + 16);
    store_32_le(state[9], key + 20);
    store_32_le(state[10], key + 24);
    store_32_le(state[11], key + 28);
    state[12] = counter;
    store_32_le(state[13], nonce);
    store_32_le(state[14], nonce + 4);
    store_32_le(state[15], nonce + 8);
}

#define increment_counter(state) (state)[12]++

// source: http://blog.regehr.org/archives/1063
#define rotl32a(x, n) ((x) << (n)) | ((x) >> (32 - (n)))

#define Qround(a,b,c,d) \
    a += b; d ^= a; d = rotl32a(d, 16); \
    c += d; b ^= c; b = rotl32a(b, 12); \
    a += b; d ^= a; d = rotl32a(d, 8); \
    c += d; b ^= c; b = rotl32a(b, 7);

#define TIMES16(x) \
    x(0) x(1) x(2)  x(3)  x(4)  x(5)  x(6)  x(7) \
    x(8) x(9) x(10) x(11) x(12) x(13) x(14) x(15)

static void core_block(const uint32_t *restrict start, uint32_t *restrict output) {
    // instead of working on the output array, 
    // we let the compiler allocate 16 local variables on the stack
    #define __LV(i) uint32_t __s##i = start[i];
    TIMES16(__LV)

    #define __Q(a,b,c,d) Qround(__s##a, __s##b, __s##c, __s##d)

    for (int i = 0; i < 10; i++) {
        __Q(0, 4,  8, 12);
        __Q(1, 5,  9, 13);
        __Q(2, 6, 10, 14);
        __Q(3, 7, 11, 15);
        __Q(0, 5, 10, 15);
        __Q(1, 6, 11, 12);
        __Q(2, 7,  8, 13);
        __Q(3, 4,  9, 14);
    }

    #define __FIN(i) output[i] = start[i] + __s##i;
    TIMES16(__FIN)
}

#define U8(x) ((uint8_t)((x) & 0xFF))


#ifdef FAST_PATH
#   define xor32_le(dst, src, pad) \
    uint32_t __value; \
    memcpy(&__value, src, sizeof(uint32_t)); \
    __value ^= *(pad); \
    memcpy(dst, &__value, sizeof(uint32_t));
#else
#   define xor32_le(dst, src, pad) \
    (dst)[0] = (src)[0] ^ U8(*(pad)); \
    (dst)[1] = (src)[1] ^ U8(*(pad) >> 8); \
    (dst)[2] = (src)[2] ^ U8(*(pad) >> 16); \
    (dst)[3] = (src)[3] ^ U8(*(pad) >> 24);
#endif

#define index8_32(a, ix) ((a) + ((ix) * sizeof(uint32_t)))

#define xor32_blocks(dest, source, pad, words) \
    for (unsigned int __i = 0; __i < words; __i++) { \
        xor32_le(index8_32(dest, __i), index8_32(source, __i), (pad) + __i) \
    }


static void xor_block(uint8_t *restrict dest, const uint8_t *restrict source, const uint32_t *restrict pad, unsigned int chunk_size) {
    unsigned int full_blocks = chunk_size / sizeof(uint32_t);
    // have to be carefull, we are going back from uint32 to uint8, so endianess matters again
    xor32_blocks(dest, source, pad, full_blocks)

    dest += full_blocks * sizeof(uint32_t);
    source += full_blocks * sizeof(uint32_t);
    pad += full_blocks;

    switch(chunk_size % sizeof(uint32_t)) {
        case 1:
            dest[0] = source[0] ^ U8(*pad);
            break;
        case 2:
            dest[0] = source[0] ^ U8(*pad);
            dest[1] = source[1] ^ U8(*pad >> 8);
            break;
        case 3:
            dest[0] = source[0] ^ U8(*pad);
            dest[1] = source[1] ^ U8(*pad >> 8);
            dest[2] = source[2] ^ U8(*pad >> 16);
            break;
    }
}

void chacha20_xor_stream(
        uint8_t *restrict dest, 
        const uint8_t *restrict source, 
        size_t length,
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
) {
    uint32_t state[CHACHA20_STATE_WORDS];
    initialize_state(state, key, nonce, counter);

    uint32_t pad[CHACHA20_STATE_WORDS];
    size_t full_blocks = length / CHACHA20_BLOCK_SIZE;
    for (size_t b = 0; b < full_blocks; b++) {
        core_block(state, pad);
        increment_counter(state);
        xor32_blocks(dest, source, pad, CHACHA20_STATE_WORDS)
        dest += CHACHA20_BLOCK_SIZE;
        source += CHACHA20_BLOCK_SIZE;
    }
    unsigned int last_block = (unsigned int)(length % CHACHA20_BLOCK_SIZE);
    if (last_block > 0 ) {
        core_block(state, pad);
        xor_block(dest, source, pad, last_block);
    }
}


#ifdef FAST_PATH
#define serialize(poly_key, result) memcpy(poly_key, result, 32)
#else
#define store32_le(target, source) \
    (target)[0] = U8(*(source)); \
    (target)[1] = U8(*(source) >> 8); \
    (target)[2] = U8(*(source) >> 16); \
    (target)[3] = U8(*(source) >> 24);

#define serialize(poly_key, result) \
    for (unsigned int i = 0; i < 32 / sizeof(uint32_t); i++) { \
        store32_le(index8_32(poly_key, i), result + i); \
    }
#endif



void rfc8439_keygen(
        uint8_t poly_key[32],
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE]
) {
    uint32_t state[CHACHA20_STATE_WORDS];
    uint32_t result[CHACHA20_STATE_WORDS];
    initialize_state(state, key, nonce, 0);
    core_block(state, result);
    serialize(poly_key, result);
}
