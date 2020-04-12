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

#define MAX_TEST_SIZE (8*1024*1024)

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

struct bench_data {
    uint8_t plain[MAX_TEST_SIZE];
    uint8_t ad[MAX_TEST_SIZE];
    uint8_t key[RFC_8439_KEY_SIZE];
    uint8_t nonce[RFC_8439_NONCE_SIZE];
    uint8_t buffer1[MAX_TEST_SIZE];
    uint8_t buffer2[MAX_TEST_SIZE];
};

#define RUNS (20)

struct run_data {
    struct timespec begin[RUNS];
    struct timespec end[RUNS];
    double times[RUNS];
};

static inline double duration(struct timespec *begin, struct timespec *end) {
    return (end->tv_nsec - begin->tv_nsec) / 1000000000.0 + (end->tv_sec  - begin->tv_sec);
}

static void bench_process(struct run_data *runs) {
    for (int i = 0; i< RUNS; i++){
        runs->times[i] = duration(&(runs->begin[i]), &(runs->end[i]));
    }

    // bubble sort times array for quicker statistics and removing outliers
    for (int i = 0; i < RUNS - 1; i++) {
        for (int j = i + 1; j < RUNS; j++) {
            if (runs->times[j] < runs->times[i]) {
                double temp = runs->times[i];
                runs->times[i] = runs->times[j];
                runs->times[j] = temp;
            }
        }
    }
}

static inline double bench_min(struct run_data *runs) {
    return runs->times[1];
}

static inline double bench_max(struct run_data *runs) {
    return runs->times[RUNS - 2];
}



static double bench_median(struct run_data *runs) {
    if (RUNS % 2 == 0) { // even so take mean of two center points
        return ((runs->times[RUNS / 2] + runs->times[RUNS / 2 - 1]) / 2);
    }
    else {
        return runs->times[RUNS / 2];
    }
}

#define TICK(rd, i) clock_gettime(CLOCK_MONOTONIC_RAW, &(rd->begin[i]))
#define TOCK(rd, i) clock_gettime(CLOCK_MONOTONIC_RAW, &(rd->end[i]))

static void chacha_round(struct bench_data *bd, struct run_data* runs, size_t test_size) {
    for (int i = 0; i < RUNS; i++) {
        TICK(runs, i);
        for (int j = 0; j < 10; j++) {
            chacha20_xor_stream(bd->buffer1, bd->plain, test_size, bd->key, bd->nonce, i);
        }
        TOCK(runs, i);
    }
    bench_process(runs);
    double min = bench_min(runs);
    double max = bench_max(runs);
    double median = bench_median(runs);
    printf("chacha20 %zu:\t %f ms ([%f..%f] aka %.3f%% spread)\n", test_size, median, min, max, ((max-min) / median) * 100);
}

static void bench_chacha(struct bench_data *bd) {
    struct run_data run;
    chacha_round(bd, &run, 1);
    chacha_round(bd, &run, 32);
    chacha_round(bd, &run, 64);
    chacha_round(bd, &run, 512);
    chacha_round(bd, &run, 1024);
    chacha_round(bd, &run, 8*1024);
    chacha_round(bd, &run, 512*1024);
    chacha_round(bd, &run, 1024*1024);
    chacha_round(bd, &run, MAX_TEST_SIZE);
}

int main(void) {
    srand(time(NULL)); 
    pcg32_random_t rng;
    rng.state = rand();
    rng.inc = rand() | 1;

    struct bench_data *bd = malloc(sizeof(struct bench_data));
    fill_crappy_random(bd->plain, MAX_TEST_SIZE, &rng);
    fill_crappy_random(bd->ad, MAX_TEST_SIZE, &rng);
    fill_crappy_random(bd->key, RFC_8439_KEY_SIZE, &rng);
    fill_crappy_random(bd->nonce, RFC_8439_NONCE_SIZE, &rng);

    bench_chacha(bd);

    free(bd);
    return 0;
}