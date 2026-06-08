#include "wlibc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    TEST_MAX_OFFSET = 63,
    TEST_MAX_LENGTH = 257,
    TEST_STORAGE_SIZE = TEST_MAX_OFFSET + TEST_MAX_LENGTH + 64,
};

static void fill_source(uint8_t *src, size_t size, size_t seed)
{
    for (size_t i = 0; i < size; ++i)
    {
        src[i] = (uint8_t) ((i * 131U + seed * 17U) & 0xFFU);
    }
}

static void call_memoryCopyLarge(void *dest, const void *src, intmax_t n)
{
    memoryCopyLarge(dest, src, n);
}

static void test_misaligned_copy(void (*copy_fn)(void *, const void *, intmax_t), const char *name)
{
    uint8_t src[TEST_STORAGE_SIZE];
    uint8_t expected[TEST_STORAGE_SIZE];
    uint8_t actual[TEST_STORAGE_SIZE];

    for (size_t dst_offset = 0; dst_offset <= TEST_MAX_OFFSET; ++dst_offset)
    {
        for (size_t src_offset = 0; src_offset <= TEST_MAX_OFFSET; ++src_offset)
        {
            for (size_t length = 0; length <= TEST_MAX_LENGTH; ++length)
            {
                fill_source(src, sizeof(src), dst_offset + src_offset + length);
                memset(expected, 0xA5, sizeof(expected));
                memset(actual, 0xA5, sizeof(actual));

                memcpy(expected + dst_offset, src + src_offset, length);
                copy_fn(actual + dst_offset, src + src_offset, (intmax_t) length);

                if (memcmp(actual, expected, sizeof(actual)) != 0)
                {
                    fprintf(stderr, "%s mismatch at dst_offset=%zu src_offset=%zu length=%zu\n", name, dst_offset,
                            src_offset, length);
                    exit(1);
                }
            }
        }
    }
}

int main(void)
{
    test_misaligned_copy(call_memoryCopyLarge, "memoryCopyLarge");
    test_misaligned_copy(wwMemoryCopyLarge, "wwMemoryCopyLarge");
    return 0;
}
