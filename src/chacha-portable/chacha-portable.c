#include "chacha-portable.h"
#include <string.h>
#include <assert.h>

#define CHACHA20_STATE_WORDS (16)

static inline uint32_t load32_le(const uint8_t *source) {
    #if defined(UNALIGNED_32BIT_ACCESS) && defined(__LITTLE_ENDIAN) && CHAR_BIT == 8
    return *((const uint32_t*)source; 
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

static void quarter_round(uint32_t s[CHACHA20_STATE_WORDS], int a, int b, int c, int d) {
    Qround(s[a], s[b], s[c], s[d])
}

static void core_block(const uint32_t start[CHACHA20_STATE_WORDS], uint32_t output[CHACHA20_STATE_WORDS]) {
    #if defined(BIG_STACK) && !defined(OPTIMIZE_SIZE)
    #define __LV(i) uint32_t __s##i = start[i];
    __LV(0) __LV(1) __LV(2)  __LV(3)  __LV(4)  __LV(5)  __LV(6)  __LV(7)
    __LV(8) __LV(9) __LV(10) __LV(11) __LV(12) __LV(13) __LV(14) __LV(15)
    #undef __LV

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
    #undef __Q

    #define __FIN(i) output[i] = start[i] + __s##i;
    __FIN(0) __FIN(1) __FIN(2)  __FIN(3)  __FIN(4)  __FIN(5)  __FIN(6)  __FIN(7)
    __FIN(8) __FIN(9) __FIN(10) __FIN(11) __FIN(12) __FIN(13) __FIN(14) __FIN(15)

    #else
    memcpy(output, start, CHACHA20_STATE_WORDS * sizeof(uint32_t));

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

static inline void xor32_le(uint8_t* dst, const uint8_t* src, const uint32_t* pad) {
    #if defined(UNALIGNED_32BIT_ACCESS) && defined(__LITTLE_ENDIAN) && CHAR_BIT == 8
    ((uint32_t*)((void*)dst))[0] = ((const uint32_t*)((const void*)dst))[0] ^ *pad;
    #else
    dst[0] = src[0] ^ (uint8_t)(*pad & 0xFF);
    dst[1] = src[1] ^ (uint8_t)((*pad >> 8) & 0xFF);
    dst[2] = src[2] ^ (uint8_t)((*pad >> 16) & 0xFF);
    dst[3] = src[3] ^ (uint8_t)((*pad >> 24) & 0xFF);
    #endif
}

static void xor(void *dest, const void* source, uint32_t pad[CHACHA20_STATE_WORDS], int chunk_size) {
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
            dst[2] = src[2] ^ (uint8_t)((*pad >> 16) & 0xFF);
        case 2:
            dst[1] = src[1] ^ (uint8_t)((*pad >> 8) & 0xFF);
        case 1:
            dst[0] = src[0] ^ (uint8_t)((*pad) & 0xFF);
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
        xor(dst, src, pad, block_size);
        length -= block_size;
        dst += block_size;
        src += block_size;
    }
}