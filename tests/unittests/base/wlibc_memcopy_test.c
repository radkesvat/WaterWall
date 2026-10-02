/*
 * Covers: wlibc memcopy; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: test_misaligned_copy, test_large_copy
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.wlibc_memcopy_unit
 */
#include "wlibc.h"

enum
{
    TEST_MAX_OFFSET   = 63,
    TEST_MAX_LENGTH   = 257,
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
                    fprintf(stderr,
                            "%s mismatch at dst_offset=%zu src_offset=%zu length=%zu\n",
                            name,
                            dst_offset,
                            src_offset,
                            length);
                    exit(1);
                }
            }
        }
    }
}

static void test_large_copy(void (*copy_fn)(void *, const void *, intmax_t), const char *name)
{
    static uint8_t src[131073 + 128], expected[sizeof(src)], actual[sizeof(src)];
    const size_t   lengths[] = {511, 512, 513, 1460, 4095, 4096, 4097, 65535, 65536, 131073};
    const size_t   offsets[] = {0, 1, 7, 16, 31, 32, 63};
    fill_source(src, sizeof(src), 37);
    for (size_t d = 0; d < ARRAY_SIZE(offsets); ++d)
    {
        for (size_t s = 0; s < ARRAY_SIZE(offsets); ++s)
        {
            for (size_t n = 0; n < ARRAY_SIZE(lengths); ++n)
            {
                memset(expected, 0xa5, sizeof(expected));
                memset(actual, 0xa5, sizeof(actual));
                memcpy(expected + offsets[d], src + offsets[s], lengths[n]);
                copy_fn(actual + offsets[d], src + offsets[s], (intmax_t) lengths[n]);
                if (memcmp(actual, expected, sizeof(actual)) != 0)
                {
                    fprintf(stderr,
                            "%s large mismatch at dst_offset=%zu src_offset=%zu length=%zu\n",
                            name,
                            offsets[d],
                            offsets[s],
                            lengths[n]);
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
    test_large_copy(call_memoryCopyLarge, "memoryCopyLarge");
    test_large_copy(wwMemoryCopyLarge, "wwMemoryCopyLarge");
    return 0;
}
