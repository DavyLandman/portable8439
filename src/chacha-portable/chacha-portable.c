#include "chacha-portable.h"
#include <string.h>
#include <assert.h>

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

#if defined(__HAVE_LITTLE_ENDIAN) && !defined(TEST_SLOW_PATH)
#define FAST_PATH
#endif


#define CHACHA20_STATE_WORDS (16)


static inline uint32_t load32_le(const uint8_t *source) {
    #ifdef FAST_PATH
    uint32_t result;
    memcpy(&result, source, 4);
    return result;
    #else
    return 
           (uint32_t)source[0]
        | ((uint32_t)source[1]) << 8
        | ((uint32_t)source[2]) << 16
        | ((uint32_t)source[3]) << 24
        ;
    #endif
}

static void initialize_state(
        uint32_t state[CHACHA20_STATE_WORDS], 
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
) {
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;
    state[4]  = load32_le(key);
    state[5]  = load32_le(key + 4);
    state[6]  = load32_le(key + 8);
    state[7]  = load32_le(key + 12);
    state[8]  = load32_le(key + 16);
    state[9]  = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);
    state[12] = counter;
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);
}

static inline void increment_counter(uint32_t state[CHACHA20_STATE_WORDS]) {
    state[12]++;
}

// source: http://blog.regehr.org/archives/1063
static inline uint32_t rotl32a(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

#define Qround(a,b,c,d) \
    a += b; d ^= a; d = rotl32a(d, 16); \
    c += d; b ^= c; b = rotl32a(b, 12); \
    a += b; d ^= a; d = rotl32a(d, 8); \
    c += d; b ^= c; b = rotl32a(b, 7);

static inline void quarter_round(uint32_t s[CHACHA20_STATE_WORDS], int a, int b, int c, int d) {
    Qround(s[a], s[b], s[c], s[d])
}

#define TIMES16(x) \
    x(0) x(1) x(2)  x(3)  x(4)  x(5)  x(6)  x(7) \
    x(8) x(9) x(10) x(11) x(12) x(13) x(14) x(15)

static void core_block(const uint32_t start[CHACHA20_STATE_WORDS], uint32_t output[CHACHA20_STATE_WORDS]) {
    #if !defined(__OPTIMIZE_SIZE__) && !defined(__NO_INLINE__)
    // instead of working on the array, we let the compiler allocate 16 local variables on the stack
    // this saves quite some speed
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
    #else
    memcpy(output, start, CHACHA20_STATE_WORDS * 4);

    for (int i = 0; i < 10; i++) {
        quarter_round(output, 0, 4,  8, 12);
        quarter_round(output, 1, 5,  9, 13);
        quarter_round(output, 2, 6, 10, 14);
        quarter_round(output, 3, 7, 11, 15);
        quarter_round(output, 0, 5, 10, 15);
        quarter_round(output, 1, 6, 11, 12);
        quarter_round(output, 2, 7,  8, 13);
        quarter_round(output, 3, 4,  9, 14);
    }

    for (int i = 0; i < CHACHA20_STATE_WORDS; i++) {
        output[i] += start[i];
    }
    #endif
}

#define U8(x) ((uint8_t)((x) & 0xFF))

static inline void xor32_le(uint8_t* dst, const uint8_t* src, const uint32_t* pad) {
    #ifdef FAST_PATH
    uint32_t value;
    memcpy(&value, src, 4);
    value ^= *pad;
    memcpy(dst, &value, 4);
    #else
    dst[0] = src[0] ^ U8(*pad);
    dst[1] = src[1] ^ U8(*pad >> 8);
    dst[2] = src[2] ^ U8(*pad >> 16);
    dst[3] = src[3] ^ U8(*pad >> 24);
    #endif
}

static void xor_block(void *dest, const void* source, const uint32_t pad[CHACHA20_STATE_WORDS], int chunk_size) {
    int full_blocks = chunk_size / sizeof(uint32_t);
    // have to be carefull, we are going back from uint32 to uint8, so endianess matters again
    uint8_t* dst = dest;
    const uint8_t* src = source;
    for (int i = 0; i < full_blocks; i++) {
        xor32_le(dst, src, pad);
        pad++;
        dst += sizeof(uint32_t);
        src += sizeof(uint32_t);
    }
    switch(chunk_size % sizeof(uint32_t)) {
        case 3:
            dst[2] = src[2] ^ U8(*pad >> 16);
        case 2:
            dst[1] = src[1] ^ U8(*pad >> 8);
        case 1:
            dst[0] = src[0] ^ U8(*pad);
    }
}

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
void chacha20_xor_stream(
        void *dest, 
        const void *source, 
        size_t length,
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE],
        uint32_t counter
) {
    uint32_t state[CHACHA20_STATE_WORDS] = {0};
    initialize_state(state, key, nonce, counter);

    uint32_t pad[CHACHA20_STATE_WORDS] = {0};
    uint8_t* dst = dest;
    const uint8_t* src = source;
    while (length > 0) {
        core_block(state, pad);
        increment_counter(state);

        int block_size = (int)(MIN(CHACHA20_STATE_WORDS * sizeof(uint32_t), length));
        xor_block(dst, src, pad, block_size);
        length -= block_size;
        dst += block_size;
        src += block_size;
    }
}

static inline void store32_le(uint8_t *target, const uint32_t *source) {
    #ifdef FAST_PATH
    memcpy(target, source, 4);
    #else
    target[0] = U8(*source);
    target[1] = U8(*source >> 8);
    target[2] = U8(*source >> 16);
    target[3] = U8(*source >> 24);
    #endif
}

void rfc8439_keygen(
        uint8_t poly_key[32],
        const uint8_t key[CHACHA20_KEY_SIZE],
        const uint8_t nonce[CHACHA20_NONCE_SIZE]
) {
    uint32_t state[CHACHA20_STATE_WORDS] = {0};
    uint32_t result[CHACHA20_STATE_WORDS] = {0};
    initialize_state(state, key, nonce, 0);
    core_block(state, result);
    //serialize
    #ifdef __UNALIGNED_FAST
    memcpy(poly_key, result, 32);
    #else
    for (int i = 0; i < 32 / 4; i++) {
        store32_le(poly_key + (i * 4), result + i);
    }
    #endif
}