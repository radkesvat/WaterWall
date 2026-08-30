/*
 * Non-gating benchmark for the fastRand / getRandomBytes family.
 *
 * Measures:
 *   - 50 million fastRand32() calls
 *   - 50 million fastRand64() calls
 *   - 10 million 16-byte getRandomBytes() fills
 *   - 5 million 64-byte getRandomBytes() fills
 *
 * 1 warm-up iteration followed by 5 timed sample iterations; reports median ns/op.
 */

#include "wwapi.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

enum
{
    kSampleRuns            = 5,
    kRand32Iterations      = 50000000,
    kRand64Iterations      = 50000000,
    kRand16BytesIterations = 10000000,
    kRand64BytesIterations = 5000000
};

static uint64_t benchmarkNowNs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

static int compareUint64(const void *a, const void *b)
{
    uint64_t arg1 = *(const uint64_t *) a;
    uint64_t arg2 = *(const uint64_t *) b;
    if (arg1 < arg2)
        return -1;
    if (arg1 > arg2)
        return 1;
    return 0;
}

static uint64_t median5(uint64_t samples[5])
{
    uint64_t sorted[5];
    for (int i = 0; i < 5; ++i)
    {
        sorted[i] = samples[i];
    }
    qsort(sorted, 5, sizeof(uint64_t), compareUint64);
    return sorted[2];
}

static volatile uint64_t g_sink = 0;

static uint64_t benchFastRand32(size_t iterations)
{
    uint64_t       sum   = 0;
    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        sum += fastRand32();
    }
    const uint64_t elapsed = benchmarkNowNs() - start;
    g_sink += sum;
    return elapsed;
}

static uint64_t benchFastRand64(size_t iterations)
{
    uint64_t       sum   = 0;
    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        sum += fastRand64();
    }
    const uint64_t elapsed = benchmarkNowNs() - start;
    g_sink += sum;
    return elapsed;
}

static uint64_t benchGetRandomBytes16(size_t iterations)
{
    uint8_t        buf[16];
    uint64_t       sum   = 0;
    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        getRandomBytes(buf, sizeof(buf));
        sum += buf[0] + buf[15];
    }
    const uint64_t elapsed = benchmarkNowNs() - start;
    g_sink += sum;
    return elapsed;
}

static uint64_t benchGetRandomBytes64(size_t iterations)
{
    uint8_t        buf[64];
    uint64_t       sum   = 0;
    const uint64_t start = benchmarkNowNs();
    for (size_t i = 0; i < iterations; ++i)
    {
        getRandomBytes(buf, sizeof(buf));
        sum += buf[0] + buf[63];
    }
    const uint64_t elapsed = benchmarkNowNs() - start;
    g_sink += sum;
    return elapsed;
}

int main(void)
{
    if (! globalstateInitializeSecureRandom())
    {
        fputs("wfrand_benchmark: secure random provider initialization failed\n", stderr);
        return 1;
    }
    if (! frandGlobalInit())
    {
        fputs("wfrand_benchmark: fast random global initialization failed\n", stderr);
        globalstateDestroySecureRandom();
        return 1;
    }
    frandInit();

    printf("Running wfrand_benchmark (warm-up + %d samples)...\n", kSampleRuns);

    // Warm-up
    (void) benchFastRand32(1000000);
    (void) benchFastRand64(1000000);
    (void) benchGetRandomBytes16(500000);
    (void) benchGetRandomBytes64(500000);

    uint64_t r32_samples[kSampleRuns];
    uint64_t r64_samples[kSampleRuns];
    uint64_t b16_samples[kSampleRuns];
    uint64_t b64_samples[kSampleRuns];

    for (int s = 0; s < kSampleRuns; ++s)
    {
        r32_samples[s] = benchFastRand32(kRand32Iterations);
        r64_samples[s] = benchFastRand64(kRand64Iterations);
        b16_samples[s] = benchGetRandomBytes16(kRand16BytesIterations);
        b64_samples[s] = benchGetRandomBytes64(kRand64BytesIterations);
        printf("  Sample %d complete\n", s + 1);
    }

    uint64_t r32_med = median5(r32_samples);
    uint64_t r64_med = median5(r64_samples);
    uint64_t b16_med = median5(b16_samples);
    uint64_t b64_med = median5(b64_samples);

    double r32_ns_op   = (double) r32_med / (double) kRand32Iterations;
    double r64_ns_op   = (double) r64_med / (double) kRand64Iterations;
    double b16_ns_op   = (double) b16_med / (double) kRand16BytesIterations;
    double b16_ns_byte = (double) b16_med / ((double) kRand16BytesIterations * 16.0);
    double b64_ns_op   = (double) b64_med / (double) kRand64BytesIterations;
    double b64_ns_byte = (double) b64_med / ((double) kRand64BytesIterations * 64.0);

    printf("\nResults (Median of %d samples):\n", kSampleRuns);
    printf("  fastRand32:             %6.2f ns/word (%zu ops, total %" PRIu64 " ms)\n",
           r32_ns_op,
           (size_t) kRand32Iterations,
           (uint64_t) (r32_med / 1000000ULL));
    printf("  fastRand64:             %6.2f ns/word (%zu ops, total %" PRIu64 " ms)\n",
           r64_ns_op,
           (size_t) kRand64Iterations,
           (uint64_t) (r64_med / 1000000ULL));
    printf("  getRandomBytes(16B):    %6.2f ns/fill (%6.2f ns/byte, %zu ops, total %" PRIu64 " ms)\n",
           b16_ns_op,
           b16_ns_byte,
           (size_t) kRand16BytesIterations,
           (uint64_t) (b16_med / 1000000ULL));
    printf("  getRandomBytes(64B):    %6.2f ns/fill (%6.2f ns/byte, %zu ops, total %" PRIu64 " ms)\n",
           b64_ns_op,
           b64_ns_byte,
           (size_t) kRand64BytesIterations,
           (uint64_t) (b64_med / 1000000ULL));

    if (g_sink == 0)
    {
        printf("sink: %" PRIu64 "\n", g_sink);
    }

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();

    return 0;
}
