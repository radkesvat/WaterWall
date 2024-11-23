// #include "asmlib.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <x86intrin.h>

static inline void A_memcpy(void *dest, const void *src, size_t n)
{
    // d, s -> 128 byte aligned
    // n -> multiple of 128
    __m256i       *d_vec  = (__m256i *) (((uintptr_t) dest) & (~(uintptr_t)127));
    const __m256i *s_vecc = (const __m256i *) (((uintptr_t) src) & (~(uintptr_t)127));
    size_t         n_vec  = 4 + (n / sizeof(__m256i));
    // memcpy(d_vec,s_vecc,n_vec * 32);

    while (n_vec > 0)
    {
        _mm256_store_si256(d_vec, _mm256_load_si256(s_vecc));
        _mm256_store_si256(d_vec + 1, _mm256_load_si256(s_vecc + 1));
        _mm256_store_si256(d_vec + 2, _mm256_load_si256(s_vecc + 2));
        _mm256_store_si256(d_vec + 3, _mm256_load_si256(s_vecc + 3));
        n_vec -= 4;
        s_vecc += 4;
        d_vec += 4;
    }
}


#define SIZE       (1ULL << 23) // Size of the memory block to copy (in bytes)
#define ITERATIONS 1000           // Number of iterations for benchmarking

int main()
{
    // size_t csize = GetMemcpyCacheLimit();
    // printf("GetMemcpyCacheLimit: %lu\n",csize);


    char   *source      = 128+malloc(SIZE+128);
    char   *destination = 128+malloc(SIZE+128);
    clock_t start, end;
    double  cpu_time_used;

    // Initialize the source array
    memset(source, 'A', SIZE);
    A_memcpy(destination, source, SIZE);
    memcpy(destination, source, SIZE);

    // Benchmarking A_memcpy
    start = clock();
    for (int i = 0; i < ITERATIONS; ++i)
    {
        A_memcpy(destination, source, SIZE);
    }
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time taken by A_memcpy for %d iterations of copying %lld bytes: %f seconds\n", ITERATIONS, SIZE,
           cpu_time_used);

    // Benchmarking memcpy
    start = clock();
    for (int i = 0; i < ITERATIONS; ++i)
    {
        memcpy(destination, source, SIZE);
    }
    end = clock();

    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

    printf("Time taken by memcpy for %d iterations of copying %lld bytes: %f seconds\n", ITERATIONS, SIZE,
           cpu_time_used);


    return 0;
}
