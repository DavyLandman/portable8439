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

struct bench_data {
    uint8_t plain[MAX_TEST_SIZE];
    uint8_t ad[MAX_TEST_SIZE];
    uint8_t key[RFC_8439_KEY_SIZE];
    uint8_t nonce[RFC_8439_NONCE_SIZE];
    uint8_t buffer1[MAX_TEST_SIZE];
    uint8_t buffer2[MAX_TEST_SIZE];
};


static void sort_double_array(double *array, size_t len) {
    // bubble sort times array for quicker statistics and removing outliers
    for (size_t i = 0; i < len - 1; i++) {
        for (size_t j = i + 1; j < len; j++) {
            if (array[j] < array[i]) {
                double temp = array[i];
                array[i] = array[j];
                array[j] = temp;
            }
        }
    }
}


static double median_double_array(const double *array, size_t len) {
    if (len % 2 == 0) {
        return (array[len / 2] + array[len / 2 - 1]) / 2;
    }
    return array[len / 2];
}

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif


#define BENCH(X, Y, Z) \
    static double bench__##X(struct bench_data *bd, size_t test_size) {  \
        printf("%s bench %zu (0x%zx): \t", Y, test_size, test_size); \
        uint32_t runs = 20; \
        while (true) { \
            clock_t tick = clock(); \
            for (uint32_t r = 0; r < runs; r++) { \
                Z; \
            }\
            clock_t tock = clock(); \
            double took = (double)(tock - tick) / CLOCKS_PER_SEC; \
            if (took >= 3) { \
                /* more than 3 seconds seems enough runs to measure speed */ \
                double speed = ((((double)runs * test_size) / (took)) / (1024*1024)); \
                printf("%.1f MiB/s\n", speed); \
                return speed; \
            } \
            runs <<= 1; \
        } \
    }

BENCH(chacha, "chacha20", chacha20_xor_stream(bd->buffer1, bd->plain, test_size, bd->key, bd->nonce, r))

#define MIN(a,b) ((a) > (b) ? (b) : (a))
BENCH(chacha_poly, "chacha20-poly1305", portable_chacha20_poly1305_encrypt(bd->buffer2, bd->buffer1, bd->key, bd->nonce, bd->ad, MIN(test_size, 512), bd->plain, test_size))

static const size_t test_sizes[] = {
    32, 63, 64, 511, 512, 1024, 8*1024, 32*1024, 64*1024, 128*1024, 512*1024, 1024*1024, MAX_TEST_SIZE
};

#define TEST_SIZES_LENGTH (sizeof(test_sizes)/sizeof(size_t))


static void report_speeds(double speeds[TEST_SIZES_LENGTH]) {
    sort_double_array(speeds, TEST_SIZES_LENGTH);

    printf("Median speed: %.1f MB/s\n", median_double_array(speeds, TEST_SIZES_LENGTH));
    printf("Speed range: %.1f MB/s, %.1f MB/s...%.1f MB/s, %.1f MB/s\n", speeds[0], speeds[1], speeds[TEST_SIZES_LENGTH - 2], speeds[ TEST_SIZES_LENGTH - 1]);
}

static void bench_chacha(struct bench_data *bd) {
    double speeds[TEST_SIZES_LENGTH];
    printf("Running chacha20 benchmarks\n");
    for (size_t i = 0; i < TEST_SIZES_LENGTH; i++) {
        speeds[i] = bench__chacha(bd, test_sizes[i]);
    }
    report_speeds(speeds);
}

static void bench_chacha_poly(struct bench_data *bd) {
    double speeds[TEST_SIZES_LENGTH];
    printf("Running chacha20-poly1305 benchmarks\n");
    for (size_t i = 0; i < TEST_SIZES_LENGTH; i++) {
        speeds[i] = bench__chacha_poly(bd, test_sizes[i]);
    }
    report_speeds(speeds);
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
    bench_chacha_poly(bd);

    free(bd);
    return 0;
}