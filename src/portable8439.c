#include "portable8439.h"
#include "portable_wipe.h"
#include "chacha-portable/chacha-portable.h"
#include "poly1305-donna/poly1305-donna.h"

#define __CHACHA20_BLOCK_SIZE (64)
#define __POLY1305_KEY_SIZE (32)

static uint8_t __ZEROES[16] = { 0 };
static void pad_if_needed(poly1305_context *ctx, size_t size) {
    size_t padding = size % 16;
    if (padding != 0) {
        poly1305_update(ctx, __ZEROES, padding);
    }
}

#define __u8(v) ((uint8_t)((v) & 0xFF))

// TODO: make this depending on the unaligned/native read size possible
static void write_64bit_int(poly1305_context *ctx, uint64_t value) {
    uint8_t result[8];
    result[0] = __u8(value);
    result[1] = __u8(value >> 8);
    result[2] = __u8(value >> 16);
    result[3] = __u8(value >> 24);
    result[4] = __u8(value >> 32);
    result[5] = __u8(value >> 40);
    result[6] = __u8(value >> 48);
    result[7] = __u8(value >> 56);
    poly1305_update(ctx, result, 8);
}


static void poly1305_calculate_mac(
    uint8_t mac[RFC_8439_MAC_SIZE],
    const uint8_t *cipher_text,
    size_t cipher_text_size,
    const uint8_t key[RFC_8439_KEY_SIZE],
    const uint8_t nonce[RFC_8439_NONCE_SIZE],
    const uint8_t *ad,
    size_t ad_size
) {
    // init poly key (section 2.6)
    uint8_t poly_key[32] = {0}; 
    chacha20_xor_stream(poly_key, key, 32, key, nonce, 0);
    // start poly1305 mac
    poly1305_context poly_ctx;
    poly1305_init(&poly_ctx, poly_key);
    portable_wipe(poly_key, __POLY1305_KEY_SIZE);

    if (ad != NULL && ad_size > 0) {
        // write AD if present
        poly1305_update(&poly_ctx, ad, ad_size);
        pad_if_needed(&poly_ctx, ad_size);
    }

    // now write the cipher text
    poly1305_update(&poly_ctx, cipher_text, cipher_text_size);
    pad_if_needed(&poly_ctx, cipher_text_size);

    // write sizes
    write_64bit_int(&poly_ctx, ad_size);
    write_64bit_int(&poly_ctx, cipher_text_size);
    
    // calculate MAC
    poly1305_finish(&poly_ctx, mac);
}


void portable_chacha20_poly1305_encrypt(
    uint8_t mac[RFC_8439_MAC_SIZE],
    uint8_t *cipher_text,
    const uint8_t key[RFC_8439_KEY_SIZE],
    const uint8_t nonce[RFC_8439_NONCE_SIZE],
    const uint8_t *ad, // can be NULL for no Additional Data
    size_t ad_size,  
    const uint8_t *plain_text,
    size_t plain_text_size
) {
    chacha20_xor_stream(cipher_text, plain_text, plain_text_size, key, nonce, 1);
    poly1305_calculate_mac(mac, cipher_text, plain_text_size, key, nonce, ad, ad_size);
}

static void print_hex(const uint8_t *dt, size_t len) {
    for (int i = 0; i < len; i++) {
        if (i > 0)
            printf("");
        printf("%02X", dt[i]);
    }
    printf("\n");
}

bool portable_chacha20_poly1305_decrypt(
    uint8_t *plain_text,
    const uint8_t key[RFC_8439_KEY_SIZE],
    const uint8_t nonce[RFC_8439_NONCE_SIZE],
    const uint8_t *ad, // can be NULL for no Additional Data
    size_t ad_size,  
    const uint8_t mac[RFC_8439_MAC_SIZE],
    const uint8_t *cipher_text,
    size_t cipher_text_size
) {
    // first we calculate the mac and see if it lines up, only then do we decrypt
    uint8_t actual_mac[RFC_8439_MAC_SIZE] = { 0 };
    poly1305_calculate_mac(actual_mac, cipher_text, cipher_text_size, key, nonce, ad, ad_size);

    if (poly1305_verify(mac, actual_mac)) {
        // valid mac, so decrypt cipher_text
        chacha20_xor_stream(plain_text, cipher_text, cipher_text_size, key, nonce, 1);
        return true;
    }
    printf("Got mac: ");
    print_hex(actual_mac, RFC_8439_MAC_SIZE);
    printf("Expected mac: ");
    print_hex(mac, RFC_8439_MAC_SIZE);
    return false;
}