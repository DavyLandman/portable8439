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


typedef struct run_data {
    uint32_t rounds;
    uint32_t iterations;
    size_t bytes_per_round;
    struct timespec *begin;
    struct timespec *end;
    double *times;
} run_data;

#define MINIMAL_BYTES (100*1024*1024)
#define MINIMAL_BYTES_PER_ROUND (1024*1024)
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

static run_data* allocate_runs(size_t data_size) {
    run_data *result = malloc(sizeof(run_data));
    result->iterations = MAX(40, MINIMAL_BYTES_PER_ROUND / data_size);
    result->bytes_per_round = result->iterations * data_size;
    result->rounds = MAX(40, MINIMAL_BYTES / (result->iterations * data_size));
    result->begin = calloc(result->rounds, sizeof(struct timespec));
    result->end = calloc(result->rounds, sizeof(struct timespec));
    result->times = calloc(result->rounds, sizeof(double));
    return result;
}

static inline double duration(struct timespec *begin, struct timespec *end) {
    return (end->tv_nsec - begin->tv_nsec) / 1000000000.0 + (end->tv_sec  - begin->tv_sec);
}

static void bench_process(run_data *runs) {
    for (int i = 0; i< runs->rounds; i++){
        runs->times[i] = duration(&(runs->begin[i]), &(runs->end[i])) / runs->iterations;
    }

    // bubble sort times array for quicker statistics and removing outliers
    for (int i = 0; i < runs->rounds - 1; i++) {
        for (int j = i + 1; j < runs->rounds; j++) {
            if (runs->times[j] < runs->times[i]) {
                double temp = runs->times[i];
                runs->times[i] = runs->times[j];
                runs->times[j] = temp;
            }
        }
    }
}

static inline double bench_min(run_data *runs) {
    return runs->times[1];
}

static inline double bench_max(run_data *runs) {
    return runs->times[runs->rounds - 2];
}



static double bench_median(run_data *runs) {
    if (runs->rounds % 2 == 0) { // even so take mean of two center points
        return ((runs->times[runs->rounds / 2] + runs->times[runs->rounds / 2 - 1]) / 2);
    }
    else {
        return runs->times[runs->rounds / 2];
    }
}

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#define TICK(rd, i) clock_gettime(CLOCK_MONOTONIC_RAW, &(rd->begin[i]))
#define TOCK(rd, i) clock_gettime(CLOCK_MONOTONIC_RAW, &(rd->end[i]))

static void chacha_round(struct bench_data *bd, size_t test_size) {
    struct run_data* runs = allocate_runs(test_size);
    printf("chacha20 %zu (%d*%d):\t", test_size, runs->iterations, runs->rounds);
    for (uint32_t i = 0; i < runs->rounds; i++) {
        TICK(runs, i);
        for (uint32_t j = 0; j < runs->iterations; j++) {
            chacha20_xor_stream(bd->buffer1, bd->plain, test_size, bd->key, bd->nonce, i);
        }
        TOCK(runs, i);
    }
    bench_process(runs);
    double min = bench_min(runs);
    double max = bench_max(runs);
    double median = bench_median(runs);
    double speed = (test_size / median) / (1024*1024);
    printf("%f ms ([%f..%f] aka %.1f%% spread) \t %.3fMBps\n", median, min, max, ((max-min) / median) * 100, speed);
    free(runs);
}

static void bench_chacha(struct bench_data *bd) {
    //chacha_round(bd, 1);
    chacha_round(bd, 32);
    chacha_round(bd, 63); 
    chacha_round(bd, 64); 
    chacha_round(bd, 511);
    chacha_round(bd, 512);
    chacha_round(bd, 1024);
    chacha_round(bd, 8*1024);
    chacha_round(bd, 512*1024);
    chacha_round(bd, 1024*1024);
    chacha_round(bd, MAX_TEST_SIZE);
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