#include "splice_buffer.h"
#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif
#include "wwapi.h"

#include "buffer_pool_internal.h"
#ifdef WW_SPLICE_POOL_BYPASS_TEST
#undef BYPASS_BUFFERPOOL
#define BYPASS_BUFFERPOOL 1
#include "../../ww/bufio/buffer_pool.c"
#endif

#ifdef WW_SPLICE_POOL_FAILURE_TEST
static unsigned int fail_allocation;
void               *__real_memoryAllocate(size_t size);
void               *__wrap_memoryAllocate(size_t size);

void *__wrap_memoryAllocate(size_t size)
{
    if (fail_allocation != 0 && --fail_allocation == 0)
    {
        return NULL;
    }
    return __real_memoryAllocate(size);
}
#endif

#if WW_HAVE_SPLICE
static unsigned int pipe_calls;
static int          pipe_error;
int                 __real_pipe2(int pair[2], int flags);
int                 __wrap_pipe2(int pair[2], int flags);

int __wrap_pipe2(int pair[2], int flags)
{
    ++pipe_calls;
    if (pipe_error != 0)
    {
        errno = pipe_error;
        return -1;
    }
    return __real_pipe2(pair, flags);
}
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static uint32_t cachedSpliceCount(buffer_pool_t *pool)
{
    uint32_t large, small, splice;
    bufferpoolCachedTierCountsForTest(pool, &large, &small, &splice, NULL);
    require(large == 0 && small == 0, "splice operations touched the large/small caches");
    return splice;
}

static void checkSplice(sbuf_t *buffer, uint16_t padding)
{
    require(buffer != NULL, "splice checkout failed");
    require(sbufGetTotalCapacityNoPadding(buffer) == SPLICE_BUFFER_STORAGE_SIZE,
            "splice buffer lost its physical control-storage capacity");
    require(sbufGetLeftPadding(buffer) == padding && sbufGetLeftCapacity(buffer) == padding,
            "splice buffer has incorrect padding or cursor");
    require(sbufGetLength(buffer) == 0 && buffer->flags == kSbufFlagSplice,
            "splice checkout retained payload metadata");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
    require(metadata.pipefd[0] >= 0 && metadata.pipefd[1] >= 0 && sbufSpliceIsReusable(buffer),
            "splice checkout did not supply an empty initialized pipe");
}

static void testPipeCheckout(void)
{
#if WW_HAVE_SPLICE
    const unsigned int initial_calls = pipe_calls;
    sbuf_t            *raw           = sbufCreateSplice(33);
    require(pipe_calls == initial_calls && sbufSpliceMetadata(raw).pipefd[0] == -1 &&
                sbufSpliceMetadata(raw).pipefd[1] == -1,
            "wrapper allocation eagerly created a pipe");
    sbufDestroySplice(raw);
#endif
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(16);
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], masters[3], 8, 8192, 4096, 1024);
    require(pool != NULL, "failed to create checkout pool");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 64);
#if WW_HAVE_SPLICE
    require(pipe_calls == initial_calls, "pool construction eagerly created pipes");
    const int errors[] = {EMFILE, ENFILE};
    for (size_t i = 0; i < ARRAY_SIZE(errors); ++i)
    {
        pipe_error = errors[i];
        require(bufferpoolGetSpliceBuffer(pool) == NULL && errno == errors[i],
                "checkout did not propagate pipe creation failure");
#ifndef WW_SPLICE_POOL_BYPASS_TEST
        require(cachedSpliceCount(pool) == 4, "failed checkout lost its wrapper or recharged again");
#endif
    }
    pipe_error  = 0;
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    checkSplice(buf, 64);
    require(pipe_calls == initial_calls + ARRAY_SIZE(errors) + 1, "pool refill created pipes for spare wrappers");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    require((fcntl(metadata.pipefd[0], F_GETFL) & O_NONBLOCK) && (fcntl(metadata.pipefd[1], F_GETFL) & O_NONBLOCK) &&
                (fcntl(metadata.pipefd[0], F_GETFD) & FD_CLOEXEC) && (fcntl(metadata.pipefd[1], F_GETFD) & FD_CLOEXEC),
            "checkout returned blocking or inheritable pipe descriptors");
    bufferpoolReuseBuffer(pool, buf);
#ifndef WW_SPLICE_POOL_BYPASS_TEST
    pipe_error     = EMFILE;
    sbuf_t *reused = bufferpoolGetSpliceBuffer(pool);
    require(reused == buf && sbufSpliceMetadata(reused).pipefd[0] == metadata.pipefd[0] &&
                sbufSpliceMetadata(reused).pipefd[1] == metadata.pipefd[1] &&
                pipe_calls == initial_calls + ARRAY_SIZE(errors) + 1,
            "cached pipe checkout recreated its descriptors");
    pipe_error = 0;
    bufferpoolReuseBuffer(pool, reused);
#endif
#else
    for (unsigned int i = 0; i < 2; ++i)
        require(bufferpoolGetSpliceBuffer(pool) == NULL && errno == ENOSYS,
                "unsupported splice checkout did not return ENOSYS");
#endif
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static void testRechargeBatches(void)
{
    static const uint32_t widths[]              = {1, 2, 3, 4, 8, 256};
    sbuf_t *(*const getters[])(buffer_pool_t *) = {
        bufferpoolGetLargeBuffer, bufferpoolGetSmallBuffer, bufferpoolGetSpliceBuffer, bufferpoolGetMediumBuffer};

    for (size_t w = 0; w < ARRAY_SIZE(widths); ++w)
    {
        master_pool_t *masters[4];
        for (size_t tier = 0; tier < ARRAY_SIZE(masters); ++tier)
        {
            masters[tier] = masterpoolCreateWithCapacity(16);
            require(masters[tier] != NULL, "failed to create refill test master");
        }
        buffer_pool_t *pool = bufferpoolCreate(
            masters[0], masters[3], masters[1], masters[2], widths[w], 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024);
        require(pool != NULL, "failed to create refill test pool");
        const uint32_t batch = min(widths[w], 4U);
        for (size_t tier = 0; tier < ARRAY_SIZE(getters); ++tier)
        {
#if ! WW_HAVE_SPLICE
            if (getters[tier] == bufferpoolGetSpliceBuffer)
                continue;
#endif
            uint32_t before[4];
            bufferpoolCachedTierCountsForTest(pool, &before[0], &before[1], &before[2], &before[3]);
            sbuf_t *buffers[8];
            // Hold the first batch to force a second refill of the same tier.
            for (uint32_t i = 0; i < batch * 2U; ++i)
            {
                buffers[i] = getters[tier](pool);
                require(buffers[i] != NULL, "refill test checkout failed");
                uint32_t counts[4];
                bufferpoolCachedTierCountsForTest(pool, &counts[0], &counts[1], &counts[2], &counts[3]);
                require(counts[tier] == batch - 1U - i % batch, "refill exceeded its four-buffer or small-pool limit");
                for (size_t other = 0; other < ARRAY_SIZE(counts); ++other)
                {
                    if (other != tier)
                    {
                        require(counts[other] == before[other], "refill changed another tier's cache");
                    }
                }
            }
            for (uint32_t i = 0; i < batch * 2U; ++i)
            {
                buffers[i]->len = 0;
                bufferpoolReuseBuffer(pool, buffers[i]);
            }
        }
        bufferpoolDestroy(pool);
        for (size_t tier = 0; tier < ARRAY_SIZE(masters); ++tier)
        {
            masterpoolMakeEmpty(masters[tier]);
            masterpoolDestroy(masters[tier]);
        }
    }
}

static void testPipeDestruction(void)
{
#if WW_HAVE_SPLICE
    master_pool_t *masters[4];
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(2);
    buffer_pool_t *pool =
        bufferpoolCreate(masters[0], masters[3], masters[1], masters[2], 1, 256, MEDIUM_BUFFER_SIZE_RAM_HIGH, 64);
    sbuf_t        *buffers[12];
    int            descriptors[24];
    for (unsigned int i = 0; i < 12; ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(pool);
        require(buffers[i] != NULL, "private pipe checkout failed");
        splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffers[i]);
        descriptors[2 * i]                = metadata.pipefd[0];
        descriptors[2 * i + 1]            = metadata.pipefd[1];
    }
    // More pairs than the bounded local and master caches: overflow destroys pairs.
    for (unsigned int i = 0; i < 12; ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);
    unsigned int closed = 0;
    for (unsigned int i = 0; i < 24; ++i)
        closed += fcntl(descriptors[i], F_GETFD) < 0;
    require(closed > 0, "master overflow did not close private pipes");
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(masters[2]);
    for (unsigned int i = 0; i < 24; ++i)
        require(fcntl(descriptors[i], F_GETFD) == -1 && errno == EBADF, "pool teardown leaked a pipe");
    pool = bufferpoolCreate(masters[0], masters[3], masters[1], masters[2], 1, 256, MEDIUM_BUFFER_SIZE_RAM_HIGH, 64);
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "geometry pipe checkout failed");
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    buffer_pool_t           *other =
        bufferpoolCreate(masters[0], masters[3], masters[1], masters[2], 1, 256, MEDIUM_BUFFER_SIZE_RAM_HIGH, 64);
    bufferpoolUpdateAllocationPaddings(other, 0, 0, 0, 64);
    bufferpoolReuseBuffer(other, buf);
    require(fcntl(metadata.pipefd[0], F_GETFD) == -1 && fcntl(metadata.pipefd[1], F_GETFD) == -1,
            "incompatible pool return leaked its private pipe");
    // Install an empty reset splice wrapper in the master, then demand new geometry.
    buf = sbufCreateSplice(0);
    require(sbufSpliceInitPipe(buf, 0) == 0, "master geometry pipe creation failed");
    metadata = sbufSpliceMetadata(buf);
    sbufReset(buf);
    master_pool_item_t *item = buf;
    masterpoolReuseItems(masters[2], &item, 1);
    // Refuse the replacement pipe so its descriptor numbers cannot hide closure of the old pair.
    pipe_error = EMFILE;
    require(bufferpoolGetSpliceBuffer(other) == NULL, "replacement pipe failure was not returned");
    require(fcntl(metadata.pipefd[0], F_GETFD) == -1 && fcntl(metadata.pipefd[1], F_GETFD) == -1,
            "master geometry replacement leaked private pipes");
    pipe_error = 0;
    buf        = bufferpoolGetSpliceBuffer(other);
    checkSplice(buf, 64);
    bufferpoolReuseBuffer(other, buf);
    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
#endif
}

static void testDiscardOnPoolReturn(void)
{
#if WW_HAVE_SPLICE
    master_pool_t *masters[4];
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(2);
    buffer_pool_t *pool =
        bufferpoolCreate(masters[0], masters[3], masters[1], masters[2], 1, 256, MEDIUM_BUFFER_SIZE_RAM_HIGH, 64);
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 64);
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "discard fixture pipe checkout failed");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    require(write(metadata.pipefd[1], "BODY", 4) == 4, "discard fixture pipe write failed");
    buf->capacity = (uint32_t) buf->l_pad + 4;
    sbufSetLength(buf, 4);
    sbufShiftLeft(buf, 4);
    sbufWrite(buf, "HEAD", 4);
    bufferpoolReuseBuffer(pool, buf);
#ifdef WW_SPLICE_POOL_BYPASS_TEST
    require(fcntl(metadata.pipefd[0], F_GETFD) == -1 && fcntl(metadata.pipefd[1], F_GETFD) == -1,
            "nonempty bypass return leaked its pipe");
#else
    sbuf_t *reused = bufferpoolGetSpliceBuffer(pool);
    checkSplice(reused, 64);
    require(reused == buf && sbufSpliceIsReusable(reused) &&
                sbufSpliceMetadata(reused).pipefd[0] == metadata.pipefd[0] &&
                sbufSpliceMetadata(reused).pipefd[1] == metadata.pipefd[1],
            "pool return lost the wrapper or retained undiscarded pipe data");
    bufferpoolReuseBuffer(pool, reused);
#endif
    bufferpoolDestroy(pool);
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
#endif
}

static void testAllocationCharge(void)
{
    sbuf_t      *buf      = sbufCreateSplice(33);
    const size_t expected = sizeof(sbuf_t) + 64 + SPLICE_BUFFER_STORAGE_SIZE + kSbufAllocationAlignment;
    require(sbufGetAllocationCharge(buf) == expected, "unopened splice wrapper has wrong allocation charge");
    buf->capacity = 64 + 1024 * 1024;
    buf->len      = 1024 * 1024;
    require(sbufGetAllocationCharge(buf) == expected, "logical splice body changed physical charge");
    sbufShiftLeft(buf, 8);
    require(sbufGetAllocationCharge(buf) == expected, "splice prefix changed physical charge");
    buf->len      = 8;
    buf->capacity = 64;
    require(sbufGetAllocationCharge(buf) == expected, "consumed splice body reduced physical charge");
    buf->len = 0;
    sbufDestroy(buf);
}

int main(void)
{
    testAllocationCharge();
    testPipeCheckout();
    testDiscardOnPoolReturn();
#ifdef WW_SPLICE_POOL_BYPASS_TEST
    master_pool_t *masters[4];
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(2);
    buffer_pool_t *pool =
        bufferpoolCreate(masters[0], masters[3], masters[1], masters[2], 1, 256, MEDIUM_BUFFER_SIZE_RAM_HIGH, 64);
    sbuf_t        *buf  = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL, "bypass pipe checkout failed");
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    bufferpoolReuseBuffer(pool, buf);
    require(fcntl(metadata.pipefd[0], F_GETFD) == -1 && fcntl(metadata.pipefd[1], F_GETFD) == -1,
            "bypass return leaked its private pipe");
    bufferpoolDestroy(pool);
    for (unsigned int i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
    return 0;
#else
    testRechargeBatches();
    testPipeDestruction();
    master_pool_t *large = masterpoolCreateWithCapacity(16);
    master_pool_t *small = masterpoolCreateWithCapacity(16);
    master_pool_t *medium = masterpoolCreateWithCapacity(16);
    master_pool_t *splice = masterpoolCreateWithCapacity(16);
    require(large != NULL && small != NULL && splice != NULL, "failed to create test master pools");
    require(bufferpoolCreate(large, NULL, small, splice, 2, 4096, MEDIUM_BUFFER_SIZE_RAM_HIGH, 512) == NULL,
            "missing medium master was accepted");
    require(bufferpoolCreate(large, medium, small, NULL, 2, 4096, MEDIUM_BUFFER_SIZE_RAM_HIGH, 512) == NULL,
            "missing splice master was accepted");

#ifdef WW_SPLICE_POOL_FAILURE_TEST
    const MasterPoolItemCreateHandle original_large = large->create_item_handle;
    const MasterPoolItemCreateHandle original_small = small->create_item_handle;
    const MasterPoolItemCreateHandle original_medium = medium->create_item_handle;
    const MasterPoolItemCreateHandle original_splice = splice->create_item_handle;
    for (unsigned int allocation = 1; allocation <= 5; ++allocation)
    {
        fail_allocation = allocation;
        require(bufferpoolCreate(large, medium, small, splice, 2, 4096, MEDIUM_BUFFER_SIZE_RAM_HIGH, 512) == NULL,
                "buffer pool metadata allocation failure was not returned");
        require(fail_allocation == 0, "metadata allocation failure was not exercised");
        require(large->create_item_handle == original_large && small->create_item_handle == original_small &&
                    splice->create_item_handle == original_splice && medium->create_item_handle == original_medium,
                "failed construction published master callbacks");
    }
#endif

    buffer_pool_t *pool = bufferpoolCreate(large, medium, small, splice, 2, 4096, MEDIUM_BUFFER_SIZE_RAM_HIGH, 512);
    require(pool != NULL, "failed to create splice test pool");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 64, 33);
    require(bufferpoolGetSpliceBufferStorageSize(pool) == 32 && bufferpoolGetSpliceBufferPadding(pool) == 64,
            "splice tier getters reported incorrect geometry");
    require(cachedSpliceCount(pool) == 0, "splice cache was eagerly populated");

#if WW_HAVE_SPLICE
    sbuf_t *buffers[10];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(pool);
        checkSplice(buffers[i], 64);
    }
    buffers[0]->capacity = 64 + 8192;
    buffers[0]->len      = 8192;
    sbufShiftLeft(buffers[0], 4);
    buffers[1]->capacity = 64 + 16384;
    buffers[1]->len      = 16384;
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i]->len = 0;
        bufferpoolReuseBuffer(pool, buffers[i]);
    }
    require(cachedSpliceCount(pool) <= 4 && atomicLoadRelaxed(&splice->len) > 0,
            "splice cache did not shrink to its shared master");
    require(cachedSpliceCount(pool) + atomicLoadRelaxed(&splice->len) == ARRAY_SIZE(buffers),
            "recycling lost a splice buffer with virtual splice capacity");
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(pool);
        checkSplice(buffers[i], 64);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i]->len = 0;
        bufferpoolReuseBuffer(pool, buffers[i]);
    }

    // A second pool can draw from the shared master while requiring different headroom.
    buffer_pool_t *other = bufferpoolCreate(large, medium, small, splice, 1, 4096, MEDIUM_BUFFER_SIZE_RAM_HIGH, 512);
    require(other != NULL, "failed to create the second splice pool");
    bufferpoolUpdateAllocationPaddings(other, 64, 64, 64, 96);
    sbuf_t *buffer = bufferpoolGetSpliceBuffer(other);
    checkSplice(buffer, 96);
    bufferpoolReuseBuffer(other, buffer);

    bufferpoolDestroy(other);
#endif
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(medium);
    masterpoolMakeEmpty(splice);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(medium);
    masterpoolDestroy(splice);
    return 0;
#endif
}
