#include "../src/portable8439.h"
#include "../src/chacha-portable/chacha-portable.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "pcg_random.h"

static void fill_crappy_random(void* target, size_t length, pcg32_random_t* rng) {
    if (length >= sizeof(uint32_t)) {
        uint32_t *p = target;
        uint32_t *last = p + (length / sizeof(uint32_t));
        while (p < last) {
            *p++ = pcg32_random_r(rng);
        }
    }
    size_t tail_size = length % sizeof(uint32_t);
    if (tail_size != 0) {
        uint32_t tail = pcg32_random_r(rng);
        memcpy((((uint8_t*)target) + length) - tail_size, &tail, tail_size);
    }
}

#define MAX_TEST_SIZE (4096)
int test8439(pcg32_random_t* rng) {
    printf("Round trip chacha20-poly1305 sizes 0..4096: ");
    uint8_t plain[MAX_TEST_SIZE] = { 0};
    uint8_t ad[MAX_TEST_SIZE] = { 0 };
    uint8_t buffer[MAX_TEST_SIZE] = { 0 };
    uint8_t buffer2[MAX_TEST_SIZE] = { 0 };
    uint8_t key[RFC_8439_KEY_SIZE] = { 0 };
    uint8_t nonce[RFC_8439_NONCE_SIZE] = { 0 };

    fill_crappy_random(plain, MAX_TEST_SIZE, rng);
    fill_crappy_random(ad, MAX_TEST_SIZE, rng);

    for (int i = 0; i < MAX_TEST_SIZE; i++) {
        fill_crappy_random(key, RFC_8439_KEY_SIZE, rng);
        fill_crappy_random(nonce, RFC_8439_NONCE_SIZE, rng);

        uint8_t mac[RFC_8439_MAC_SIZE] = { 0 };
        portable_chacha20_poly1305_encrypt(mac, buffer, key, nonce, ad, i, plain, i);
        if (!portable_chacha20_poly1305_decrypt(buffer2, key, nonce, ad, i, mac, buffer, i)) {
            printf("Failed decryping (tag) %d bytes\n", i);
            return 1;
        }
        if (memcmp(buffer2, plain, i) != 0) {
            printf("Incorrect decryption at %d bytes\n", i);
            return 1;
        }
    }
    printf("success\n");
    return 0;
}

int main(void) {
    srand(time(NULL)); 
    pcg32_random_t rng;
    rng.state = rand();
    rng.inc = rand() | 1;
    return test8439(&rng);
}