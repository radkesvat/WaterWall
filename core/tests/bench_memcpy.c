#include "asmlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SIZE       (1ULL << 22) // Size of the memory block to copy (in bytes)
#define ITERATIONS 10           // Number of iterations for benchmarking

int main()
{
    size_t csize = GetMemcpyCacheLimit();
    printf("GetMemcpyCacheLimit: %lu\n",csize);


    char   *source      = malloc(SIZE);
    char   *destination = malloc(SIZE);
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
