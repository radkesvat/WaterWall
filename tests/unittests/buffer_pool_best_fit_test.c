#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

int main(void)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool         = bufferpoolCreate(large_master, small_master, 8, 8192, 1024);
    bufferpoolUpdateAllocationPaddings(pool, 64, 32);

    sbuf_t *small = bufferpoolGetBestFit(pool, 512, 16);
    require(sbufGetTotalCapacityNoPadding(small) == bufferpoolGetSmallBufferSize(pool),
            "best-fit allocator did not select the small tier");
    require(sbufGetLeftPadding(small) >= 16, "small best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, small);

    sbuf_t *large = bufferpoolGetBestFit(pool, 4096, 48);
    require(sbufGetTotalCapacityNoPadding(large) == bufferpoolGetLargeBufferSize(pool),
            "best-fit allocator did not select the large tier");
    require(sbufGetLeftPadding(large) >= 48, "large best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, large);

    sbuf_t *padding_fallback = bufferpoolGetBestFit(pool, 512, 96);
    require(sbufGetTotalCapacityNoPadding(padding_fallback) >= 512 && sbufGetLeftPadding(padding_fallback) >= 96,
            "best-fit padding fallback does not satisfy its geometry");
    require(sbufGetTotalCapacityNoPadding(padding_fallback) != bufferpoolGetSmallBufferSize(pool) ||
                sbufGetLeftPadding(padding_fallback) != bufferpoolGetSmallBufferPadding(pool),
            "best-fit allocator returned an unsuitable pooled buffer");
    bufferpoolReuseBuffer(pool, padding_fallback);

    sbuf_t *size_fallback = bufferpoolGetBestFit(pool, 16384, 24);
    require(sbufGetTotalCapacityNoPadding(size_fallback) >= 16384 && sbufGetLeftPadding(size_fallback) >= 24,
            "best-fit size fallback does not satisfy its geometry");
    bufferpoolReuseBuffer(pool, size_fallback);

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    return 0;
}
