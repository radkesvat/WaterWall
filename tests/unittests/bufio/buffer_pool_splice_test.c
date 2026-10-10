/*
 * Covers: fixed startup splice-pipe capacity, shared exhaustion, cross-thread release,
 * discard retirement and teardown, including bypassed ordinary buffer caching.
 * Setup: real pipe descriptors and buffer-pool APIs; only capacity negotiation and
 * selected allocation/splice/read failures are substituted at the OS boundary.
 * Limits: capacity negotiation is deterministic; payload/reuse/closure use real pipes.
 * CTest: waterwall.buffer_pool_splice_unit; waterwall.buffer_pool_splice_bypass_unit
 */
#include "splice_buffer.h"
#include "test_assert.h"
#include "wwapi.h"

#include "buffer_pool_internal.h"
#ifdef WW_SPLICE_POOL_BYPASS_TEST
#undef BYPASS_BUFFERPOOL
#define BYPASS_BUFFERPOOL 1
#include "../../../ww/bufio/buffer_pool.c"
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#ifdef WW_SPLICE_POOL_FAILURE_TEST
static unsigned int fail_allocation;
static unsigned int fail_aligned_allocation;
void               *__real_memoryAllocate(size_t size);
void               *__wrap_memoryAllocate(size_t size);
void               *__real_memoryAllocateAligned(size_t size, size_t alignment);
void               *__wrap_memoryAllocateAligned(size_t size, size_t alignment);

void *__wrap_memoryAllocateAligned(size_t size, size_t alignment)
{
    if (fail_aligned_allocation != 0 && --fail_aligned_allocation == 0)
        return NULL;
    return __real_memoryAllocateAligned(size, alignment);
}

void *__wrap_memoryAllocate(size_t size)
{
    if (fail_allocation != 0 && --fail_allocation == 0)
        return NULL;
    return __real_memoryAllocate(size);
}
#endif

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    kPipeCapacity         = 1024 * 1024,
    kMaximumRecordedPipes = 32
};

static unsigned int pipe_calls, query_calls, growth_calls, recorded_pipes;
static unsigned int fail_pipe_call, fail_growth_call;
static int          granted_capacity = kPipeCapacity;
static int          descriptors[kMaximumRecordedPipes][2];
static int          capacities[kMaximumRecordedPipes];
static int          drain_error_fd = -1;
static int          discard_probe_fd = -1, discard_sink_fd = -1, discard_splice_error;
static unsigned int discard_splice_calls, discard_read_calls;
static size_t       discard_splice_limit = SIZE_MAX;

int     __real_pipe2(int pair[2], int flags);
int     __wrap_pipe2(int pair[2], int flags);
int     __real_fcntl(int fd, int command, ...);
int     __wrap_fcntl(int fd, int command, ...);
ssize_t __real_read(int fd, void *bytes, size_t count);
ssize_t __wrap_read(int fd, void *bytes, size_t count);
ssize_t __real_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t count, unsigned int flags);
ssize_t __wrap_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t count, unsigned int flags);

int __wrap_pipe2(int pair[2], int flags)
{
    ++pipe_calls;
    if (fail_pipe_call != 0 && pipe_calls == fail_pipe_call)
    {
        errno = EMFILE;
        return -1;
    }
    const int result = __real_pipe2(pair, flags);
    if (result == 0)
    {
        require(recorded_pipes < kMaximumRecordedPipes, "startup exceeded bounded pipe fixture");
        descriptors[recorded_pipes][0] = pair[0];
        descriptors[recorded_pipes][1] = pair[1];
        capacities[recorded_pipes++]   = 4096;
    }
    return result;
}

int __wrap_fcntl(int fd, int command, ...)
{
    if (command == F_GETPIPE_SZ || command == F_SETPIPE_SZ)
    {
        unsigned int index = recorded_pipes;
        while (index != 0)
        {
            --index;
            if (descriptors[index][0] == fd || descriptors[index][1] == fd)
                break;
        }
        require(recorded_pipes != 0 && (descriptors[index][0] == fd || descriptors[index][1] == fd),
                "capacity query did not refer to an owned test pipe");
        if (command == F_GETPIPE_SZ)
        {
            ++query_calls;
            return capacities[index];
        }
        ++growth_calls;
        va_list args;
        va_start(args, command);
        const int requested = va_arg(args, int);
        va_end(args);
        require(requested == kPipeCapacity, "startup requested the wrong pipe capacity");
        if (fail_growth_call != 0 && growth_calls == fail_growth_call)
        {
            errno = EPERM;
            return -1;
        }
        return capacities[index] = granted_capacity;
    }
    if (command == F_GETFD || command == F_GETFL)
        return __real_fcntl(fd, command);
    va_list args;
    va_start(args, command);
    const int value = va_arg(args, int);
    va_end(args);
    return __real_fcntl(fd, command, value);
}

ssize_t __wrap_read(int fd, void *bytes, size_t count)
{
    if (fd == discard_probe_fd)
        ++discard_read_calls;
    if (fd == drain_error_fd)
    {
        drain_error_fd = -1;
        errno          = EIO;
        return -1;
    }
    return __real_read(fd, bytes, count);
}

ssize_t __wrap_splice(int in, off_t *in_offset, int out, off_t *out_offset, size_t count, unsigned int flags)
{
    if (in == drain_error_fd)
    {
        errno = EINVAL; /* Exercise the existing read-failure retirement path. */
        return -1;
    }
    if (in == discard_probe_fd)
    {
        require(in_offset == NULL && out_offset == NULL && count > 0 && (flags & SPLICE_F_NONBLOCK),
                "discard splice must be nonblocking with a positive length");
        require(discard_sink_fd < 0 || discard_sink_fd == out, "discard replaced its shared sink");
        discard_sink_fd = out;
        if (++discard_splice_calls == 2 && discard_splice_error != 0)
        {
            errno                = discard_splice_error;
            discard_splice_error = 0;
            return -1;
        }
        count = min(count, discard_splice_limit);
    }
    return __real_splice(in, in_offset, out, out_offset, count, flags);
}

static void resetProbe(void)
{
    pipe_calls = query_calls = growth_calls = recorded_pipes = 0;
    fail_pipe_call = fail_growth_call = 0;
    granted_capacity                  = kPipeCapacity;
    drain_error_fd                    = -1;
    discard_probe_fd = discard_sink_fd = -1;
    discard_splice_error               = 0;
    discard_splice_calls = discard_read_calls = 0;
    discard_splice_limit                      = SIZE_MAX;
}

static void requireClosed(int fd)
{
    require(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "inventory teardown leaked a pipe descriptor");
}

static void destroyInventory(void)
{
    sbufSplicePoolDestroy();
    require(GSTATE.splice_inventory == NULL, "teardown retained global inventory ownership");
    require(sbufSplicePoolCount() == 0 && sbufSplicePoolCapacity() == 0, "teardown retained inventory accounting");
    for (unsigned int i = 0; i < recorded_pipes; ++i)
    {
        requireClosed(descriptors[i][0]);
        requireClosed(descriptors[i][1]);
    }
}
#endif

typedef struct fixture_s
{
    master_pool_t *masters[3];
    buffer_pool_t *first;
    buffer_pool_t *second;
} fixture_t;

static buffer_pool_t *makePool(fixture_t *fixture, uint32_t width, uint16_t padding)
{
    buffer_pool_t *pool = bufferpoolCreate(fixture->masters[0],
                                           fixture->masters[1],
                                           fixture->masters[2],
                                           width,
                                           8192,
                                           MEDIUM_BUFFER_SIZE_RAM_HIGH,
                                           1024,
                                           1024 * 1024,
                                           8192);
    require(pool != NULL, "failed to create test buffer pool");
    bufferpoolUpdateAllocationPaddings(pool, padding, padding, padding, padding);
    return pool;
}

static fixture_t makeFixture(uint32_t width)
{
    fixture_t fixture = {0};
    for (size_t i = 0; i < ARRAY_SIZE(fixture.masters); ++i)
    {
        fixture.masters[i] = masterpoolCreateWithCapacity(2);
        require(fixture.masters[i] != NULL, "failed to create test master pool");
    }
    fixture.first  = makePool(&fixture, width, 64);
    fixture.second = makePool(&fixture, width, 64);
    return fixture;
}

static void destroyFixture(fixture_t *fixture)
{
    bufferpoolDestroy(fixture->first);
    bufferpoolDestroy(fixture->second);
    for (size_t i = 0; i < ARRAY_SIZE(fixture->masters); ++i)
    {
        masterpoolMakeEmpty(fixture->masters[i]);
        masterpoolDestroy(fixture->masters[i]);
    }
}

#if WW_HAVE_SPLICE
static void checkSplice(sbuf_t *buffer, uint16_t padding)
{
    require(buffer != NULL && sbufIsSplice(buffer), "splice checkout failed");
    require(sbufGetTotalCapacityNoPadding(buffer) == SPLICE_BUFFER_STORAGE_SIZE,
            "splice checkout changed physical wrapper capacity");
    require(buffer->l_pad == padding && buffer->curpos == padding && buffer->len == 0,
            "splice checkout did not restore geometry");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
    require(metadata.pipefd[0] >= 0 && metadata.pipefd[1] >= 0 && metadata.pipe_capacity >= kPipeCapacity &&
                sbufSpliceIsReusable(buffer),
            "splice checkout did not lease a full-sized empty pipe");
    require((fcntl(metadata.pipefd[0], F_GETFL) & O_NONBLOCK) && (fcntl(metadata.pipefd[1], F_GETFL) & O_NONBLOCK) &&
                (fcntl(metadata.pipefd[0], F_GETFD) & FD_CLOEXEC) && (fcntl(metadata.pipefd[1], F_GETFD) & FD_CLOEXEC),
            "inventory returned blocking or inheritable descriptors");
}

static void putBody(sbuf_t *buffer)
{
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
    require(write(metadata.pipefd[1], "BODY", 4) == 4, "failed to populate private body");
    buffer->capacity = buffer->l_pad + 4;
    sbufSetLength(buffer, 4);
    sbufShiftLeft(buffer, 4);
    sbufWrite(buffer, "HEAD", 4);
}

static void *releaseFromForeignThread(void *buffer)
{
    sbufDestroy(buffer);
    return NULL;
}

static void testStartupLimits(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(3ULL * kPipeCapacity + 123, kPipeCapacity, 20, 64) == 3,
            "startup did not floor the configured capacity budget");
    require(sbufSplicePoolCount() == 3 && sbufSplicePoolCapacity() == 3ULL * kPipeCapacity && pipe_calls == 3,
            "startup inventory exceeded its capacity budget");
    destroyInventory();

    resetProbe();
    require(sbufSplicePoolInitialize(8ULL * kPipeCapacity, kPipeCapacity, 2, 64) == 2 && pipe_calls == 2,
            "startup did not honor descriptor headroom count");
    destroyInventory();

    resetProbe();
    fail_pipe_call = 3;
    require(sbufSplicePoolInitialize(8ULL * kPipeCapacity, kPipeCapacity, 8, 64) == 2 && pipe_calls == 3,
            "startup did not retain partial inventory after pipe refusal");
    require(sbufSplicePoolCapacity() == 2ULL * kPipeCapacity, "partial inventory miscounted capacity");
    destroyInventory();

    resetProbe();
    fail_growth_call = 2;
    require(sbufSplicePoolInitialize(8ULL * kPipeCapacity, kPipeCapacity, 8, 64) == 1 && pipe_calls == 2,
            "startup retained a pipe whose full capacity was refused");
    /* The discard sink may reuse a rejected pipe's descriptor number. Check
     * every recorded descriptor after inventory and sink teardown below. */
    destroyInventory();

    resetProbe();
    granted_capacity = kPipeCapacity / 2;
    require(sbufSplicePoolInitialize(8ULL * kPipeCapacity, kPipeCapacity, 8, 64) == 0,
            "startup accepted a pipe smaller than the required capacity");
    require(pipe_calls == 1, "startup retried a rejected capacity without bound");
    destroyInventory();

    resetProbe();
    granted_capacity = 2 * kPipeCapacity;
    require(sbufSplicePoolInitialize(5ULL * kPipeCapacity, kPipeCapacity, 8, 64) == 2 &&
                sbufSplicePoolCapacity() == 4ULL * kPipeCapacity,
            "startup charged requested capacity instead of granted capacity");
    destroyInventory();

#ifdef WW_SPLICE_POOL_FAILURE_TEST
    /* Refuse either inventory metadata or the first complete buffer. */
    for (unsigned int allocation = 1; allocation <= 2; ++allocation)
    {
        resetProbe();
        fail_allocation         = allocation == 1 ? 1 : 0;
        fail_aligned_allocation = allocation == 2 ? 1 : 0;
        require(sbufSplicePoolInitialize(2ULL * kPipeCapacity, kPipeCapacity, 2, 64) == 0 && pipe_calls == 0 &&
                    fail_allocation == 0,
                "inventory metadata refusal created pipes or failed fatally");
        fixture_t unavailable = makeFixture(1);
        require(bufferpoolGetSpliceBuffer(unavailable.first) == NULL && errno == ENOBUFS,
                "unavailable startup inventory did not refuse checkout");
        sbuf_t *ordinary = bufferpoolGetLargeBuffer(unavailable.first);
        require(ordinary != NULL && ! sbufIsSplice(ordinary), "zero inventory disabled ordinary allocation");
        bufferpoolReuseBuffer(unavailable.first, ordinary);
        destroyFixture(&unavailable);
        destroyInventory();
    }
#endif

    resetProbe();
    require(sbufSplicePoolInitialize(kPipeCapacity - 1, kPipeCapacity, 8, 64) == 0 && pipe_calls == 0,
            "sub-pipe budget created a pipe");
    destroyInventory();
}

static void testGlobalStateOwnership(void)
{
    resetProbe();
    require(sbufSplicePoolPrepare() && pipe_calls == 0 && sbufSplicePoolGet(64) == NULL,
            "publishing shared control allocated pipes before padding was finalized");
    ww_global_state_t shared = *getGlobalState();
    shared.flag_initialized  = true;
    require(sbufSplicePoolInitialize(2ULL * kPipeCapacity, kPipeCapacity, 2, 64) == 2, "inventory setup failed");
    sbuf_t *held = sbufSplicePoolGet(64);
    require(held != NULL, "state-copy checkout failed");
    putBody(held);
    require(GSTATE.splice_inventory == shared.splice_inventory, "initialization replaced shared control");
    GSTATE.splice_inventory = NULL;
    require(sbufSplicePoolCount() == 0 && sbufSplicePoolGet(64) == NULL && errno == ENOBUFS,
            "splice checkout bypassed global state");
    setGlobalState(&shared);
    sbuf_t *other = sbufSplicePoolGet(64);
    require(other != NULL && sbufSplicePoolCount() == 2, "copied state lost inventory");
    sbufSpliceClosePipe(other);
    sbufDestroy(other);
    sbufDestroy(held);
    GSTATE.flag_initialized = false;
    setGlobalState(&shared);
    other = sbufSplicePoolGet(64);
    require(other == held && sbufSplicePoolCount() == 1 && sbufSplicePoolCapacity() == kPipeCapacity &&
                sbufSpliceIsReusable(other) && pipe_calls == 2,
            "state copy lost buffer identity or restored stale counters");
    sbufDestroy(other);
    destroyInventory();
    GSTATE.flag_initialized = false;
    sbufSplicePoolDestroy();
}

static void testSharedReuseAndExhaustion(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(3ULL * kPipeCapacity, kPipeCapacity, 3, 64) == 3, "inventory setup failed");
    fixture_t fixture = makeFixture(1);
    sbuf_t   *buffers[3];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(fixture.first);
        checkSplice(buffers[i], 64);
    }
    require(bufferpoolGetSpliceBuffer(fixture.first) == NULL && bufferpoolGetSpliceBuffer(fixture.second) == NULL,
            "exhausted inventory allocated another buffer");
    sbuf_t *ordinary = bufferpoolGetLargeBuffer(fixture.second);
    require(ordinary != NULL && ! sbufIsSplice(ordinary), "exhaustion prevented ordinary fallback");
    bufferpoolReuseBuffer(fixture.second, ordinary);

    sbuf_t *same = buffers[0];
    putBody(same);
    bufferpoolReuseBuffer(fixture.first, same);
#ifndef WW_SPLICE_POOL_BYPASS_TEST
    require(bufferpoolGetSpliceBuffer(fixture.second) == NULL, "another worker borrowed a private cached buffer");
#endif
    buffers[0] = bufferpoolGetSpliceBuffer(fixture.first);
    require(buffers[0] == same, "recycling replaced the complete buffer");
    checkSplice(buffers[0], 64);
    putBody(buffers[0]);
    pthread_t foreign;
    require(pthread_create(&foreign, NULL, releaseFromForeignThread, buffers[0]) == 0 &&
                pthread_join(foreign, NULL) == 0,
            "foreign return failed");
    buffers[0] = bufferpoolGetSpliceBuffer(fixture.second);
    require(buffers[0] == same, "foreign return failed to publish the complete buffer");
    checkSplice(buffers[0], 64);
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(fixture.first, buffers[i]);
    destroyFixture(&fixture);
    fixture = makeFixture(1);
    for (unsigned i = 0; i < 20; ++i)
    {
        sbuf_t *buf = bufferpoolGetSpliceBuffer(i & 1 ? fixture.first : fixture.second);
        /* A local cache may contain the entire small inventory. */
        if (buf == NULL)
            buf = bufferpoolGetSpliceBuffer(i & 1 ? fixture.second : fixture.first);
        checkSplice(buf, 64);
        sbufDestroy(buf);
    }
    require(pipe_calls == 3 && query_calls == 3 && growth_calls == 3 && sbufSplicePoolCount() == 3,
            "runtime recycling created, resized, or closed a healthy pipe");
    destroyFixture(&fixture);
    destroyInventory();
}

static void testBoundedLocalCache(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(20ULL * kPipeCapacity, kPipeCapacity, 20, 64) == 20, "cache setup failed");
    fixture_t fixture = makeFixture(256);
    sbuf_t   *buffers[20];
    for (unsigned i = 0; i < 20; ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(fixture.first);
        require(buffers[i] != NULL, "local cache cap limited active ownership");
    }
    for (unsigned i = 0; i < 20; ++i)
    {
        bufferpoolReuseBuffer(fixture.first, buffers[i]);
        uint32_t cached, large, small;
        bufferpoolCachedTierCountsForTest(fixture.first, &large, &small, &cached, NULL);
        require(cached <= 8, "splice local cache exceeded eight entries");
    }
    unsigned acquired = 0;
    while (acquired < 20 && (buffers[acquired] = bufferpoolGetSpliceBuffer(fixture.second)) != NULL)
        ++acquired;
#ifndef WW_SPLICE_POOL_BYPASS_TEST
    require(acquired == 12, "empty master did not preserve the other worker's eight cached entries");
#else
    require(acquired == 20, "bypass returned buffers were not globally available");
#endif
    while (acquired < 20)
    {
        buffers[acquired] = bufferpoolGetSpliceBuffer(fixture.first);
        require(buffers[acquired++] != NULL, "local cached inventory was lost");
    }
    for (unsigned i = 0; i < 20; ++i)
        sbufDestroy(buffers[i]);
    destroyFixture(&fixture);
    require(pipe_calls == 20 && sbufSplicePoolCount() == 20, "cache shrinking retired or replaced healthy entries");
    destroyInventory();
}

static void testImmutablePadding(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(kPipeCapacity, kPipeCapacity, 1, 33) == 1 && sbufSplicePoolPadding() == 64,
            "startup did not freeze aligned padding");
    fixture_t fixture = makeFixture(1);
    sbuf_t   *buf     = bufferpoolGetSpliceBuffer(fixture.first);
    require(buf != NULL, "padding fixture checkout failed");
    for (unsigned test = 0; test < 4; ++test)
    {
        pid_t child = fork();
        require(child >= 0, "padding fixture fork failed");
        if (child == 0)
        {
            if (test == 0)
                bufferpoolUpdateAllocationPaddings(fixture.first, 64, 64, 64, 96);
            else if (test == 1)
                discard sbufSplicePoolGet(96);
            else
            {
                buf->l_pad = 96;
                if (test == 2)
                    bufferpoolReuseBuffer(fixture.first, buf);
                else
                    sbufDestroy(buf);
            }
            _Exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) != 0,
                "changed splice padding did not terminate before metadata access");
    }
    bufferpoolReuseBuffer(fixture.first, buf);
    destroyFixture(&fixture);
    destroyInventory();
}

typedef struct concurrent_probe_s
{
    atomic_bool start;
    atomic_uint owners[2];
    atomic_uint successes;
} concurrent_probe_t;

static void *exerciseSharedInventory(void *userdata)
{
    concurrent_probe_t *probe = userdata;
    while (! atomicLoadExplicit(&probe->start, memory_order_acquire))
        YIELD_THREAD();
    for (unsigned int iteration = 0; iteration < 2000; ++iteration)
    {
        sbuf_t *buffer = sbufSplicePoolGet(64);
        if (buffer == NULL)
        {
            require(errno == ENOBUFS, "concurrent exhaustion returned an unexpected failure");
            YIELD_THREAD();
            continue;
        }
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
        const unsigned int             slot     = metadata.pipefd[0] == descriptors[0][0] ? 0 : 1;
        require(metadata.pipefd[0] == descriptors[slot][0], "checkout escaped startup inventory");
        require(atomicAddExplicit(&probe->owners[slot], 1, memory_order_acq_rel) == 0,
                "two threads simultaneously leased one pipe");
        const unsigned char expected = (unsigned char) iteration;
        unsigned char       actual   = 0;
        require(write(metadata.pipefd[1], &expected, 1) == 1 && read(metadata.pipefd[0], &actual, 1) == 1 &&
                    actual == expected,
                "concurrent leases mixed pipe contents");
        require(atomicSubExplicit(&probe->owners[slot], 1, memory_order_release) == 1,
                "concurrent lease ownership was lost");
        sbufDestroy(buffer);
        atomicAddExplicit(&probe->successes, 1, memory_order_relaxed);
    }
    return NULL;
}

static void testConcurrentLeases(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(2ULL * kPipeCapacity, kPipeCapacity, 2, 64) == 2, "concurrent setup failed");
    concurrent_probe_t probe = {0};
    pthread_t          threads[4];
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
        require(pthread_create(&threads[i], NULL, exerciseSharedInventory, &probe) == 0,
                "failed to start concurrent inventory owner");
    atomicStoreExplicit(&probe.start, true, memory_order_release);
    for (size_t i = 0; i < ARRAY_SIZE(threads); ++i)
        require(pthread_join(threads[i], NULL) == 0, "failed to join concurrent inventory owner");
    require(atomicLoadRelaxed(&probe.successes) >= 2000, "concurrent inventory did not make progress");
    require(atomicLoadRelaxed(&probe.owners[0]) == 0 && atomicLoadRelaxed(&probe.owners[1]) == 0,
            "concurrent test retained a lease");
    require(pipe_calls == 2 && query_calls == 2 && growth_calls == 2, "concurrent reuse created or resized a pipe");
    destroyInventory();
}

static void testTeardownRejectsActiveLease(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(kPipeCapacity, kPipeCapacity, 1, 64) == 1, "active-lease teardown setup failed");
    sbuf_t *buffer = sbufSplicePoolGet(64);
    require(buffer != NULL, "active-lease fixture acquisition failed");
    const pid_t child = fork();
    require(child >= 0, "active-lease teardown fork failed");
    if (child == 0)
    {
        sbufSplicePoolDestroy();
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) != 0,
            "inventory teardown accepted an outstanding lease");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
    unsigned char                  byte     = 0;
    require(write(metadata.pipefd[1], "x", 1) == 1 && read(metadata.pipefd[0], &byte, 1) == 1 && byte == 'x',
            "active lease was no longer usable after rejected teardown");
    sbufDestroy(buffer);
    destroyInventory();
}

static void testRetirement(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(2ULL * kPipeCapacity, kPipeCapacity, 2, 64) == 2, "retirement setup failed");
    fixture_t fixture = makeFixture(1);
    sbuf_t   *broken  = bufferpoolGetSpliceBuffer(fixture.first);
    sbuf_t   *held    = bufferpoolGetSpliceBuffer(fixture.first);
    checkSplice(broken, 64);
    checkSplice(held, 64);
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(broken);
    putBody(broken);
    drain_error_fd = metadata.pipefd[0];
    bufferpoolReuseBuffer(fixture.first, broken);
    requireClosed(metadata.pipefd[0]);
    requireClosed(metadata.pipefd[1]);
    require(sbufSplicePoolCount() == 1 && sbufSplicePoolCapacity() == kPipeCapacity,
            "drain failure did not retire inventory capacity");
    require(bufferpoolGetSpliceBuffer(fixture.second) == NULL && pipe_calls == 2, "runtime replaced a retired pipe");
    sbufDestroy(held);
    held = bufferpoolGetSpliceBuffer(fixture.second);
    checkSplice(held, 64);
    bufferpoolReuseBuffer(fixture.second, held);
    destroyFixture(&fixture);
    destroyInventory();
}

static void testDiscard(void)
{
    resetProbe();
    require(sbufSplicePoolInitialize(kPipeCapacity, kPipeCapacity, 1, 64) == 1, "discard setup failed");
    sbuf_t *buffer = sbufSplicePoolGet(64);
    require(buffer != NULL, "discard fixture acquisition failed");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buffer);
    discard_probe_fd                        = metadata.pipefd[0];
    const int faults[]                      = {0, EINTR, EINVAL, ENOSYS, EOPNOTSUPP, EPERM, ENOMEM};
    for (size_t i = 0; i < ARRAY_SIZE(faults); ++i)
    {
        putBody(buffer);
        discard_splice_error = faults[i];
        discard_splice_limit = i == 0 ? SIZE_MAX : 2;
        discard_splice_calls = discard_read_calls = 0;
        sbufSpliceDiscard(buffer);
        require(discard_splice_calls >= 2 && discard_splice_error == 0,
                "discard skipped its splice path or injected failure");
        require((discard_read_calls > 0) == (i > 1), "discard used the wrong fallback path");
        require(sbufSpliceIsReusable(buffer) && buffer->curpos == buffer->l_pad &&
                    sbufSpliceMetadata(buffer).pipefd[0] == metadata.pipefd[0] && sbufSplicePoolCount() == 1,
                "discard left stale data or retired a healthy pipe");
    }
    require((fcntl(discard_sink_fd, F_GETFD) & FD_CLOEXEC) && (fcntl(discard_sink_fd, F_GETFL) & O_NONBLOCK),
            "discard sink is inheritable or blocking");
    sbufShiftLeft(buffer, 4);
    sbufWrite(buffer, "HEAD", 4);
    discard_splice_calls = discard_read_calls = 0;
    sbufSpliceDiscard(buffer);
    require(discard_splice_calls == 1 && discard_read_calls == 0 && sbufSpliceIsReusable(buffer) &&
                sbufSpliceMetadata(buffer).pipefd[0] == metadata.pipefd[0],
            "prefix-only discard retired a healthy empty pipe");
    /* Materialization consumes all bytes without moving the source prefix cursor. */
    buffer->curpos = buffer->l_pad - 4;
    sbufSpliceDiscard(buffer);
    require(buffer->curpos == buffer->l_pad && sbufSpliceIsReusable(buffer),
            "empty consumed prefix retained a shifted cursor");
    sbufDestroy(buffer);
    destroyInventory();
    requireClosed(discard_sink_fd);
}
#endif

static void testOrdinaryRecharge(void)
{
#ifndef WW_SPLICE_POOL_BYPASS_TEST
    static const uint32_t widths[]              = {1, 2, 3, 4, 8, 256};
    sbuf_t *(*const getters[])(buffer_pool_t *) = {
        bufferpoolGetLargeBuffer, bufferpoolGetSmallBuffer, bufferpoolGetMediumBuffer};
    const unsigned int tier_indices[] = {0, 1, 3};
    for (size_t w = 0; w < ARRAY_SIZE(widths); ++w)
    {
        fixture_t      fixture = makeFixture(widths[w]);
        const uint32_t batch   = min(widths[w], 4U);
        for (size_t tier = 0; tier < ARRAY_SIZE(getters); ++tier)
        {
            sbuf_t *buffers[8];
            for (uint32_t i = 0; i < batch * 2U; ++i)
            {
                buffers[i] = getters[tier](fixture.first);
                uint32_t counts[4];
                bufferpoolCachedTierCountsForTest(fixture.first, &counts[0], &counts[1], &counts[2], &counts[3]);
                require(counts[tier_indices[tier]] == batch - 1U - i % batch,
                        "ordinary refill changed its bounded batch size");
            }
            for (uint32_t i = 0; i < batch * 2U; ++i)
                bufferpoolReuseBuffer(fixture.first, buffers[i]);
        }
        destroyFixture(&fixture);
    }
#endif
}

static void testConstructionFailure(void)
{
#ifndef WW_SPLICE_POOL_BYPASS_TEST
    master_pool_t *masters[3];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(2);
    require(bufferpoolCreate(
                masters[0], NULL, masters[2], 2, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 1024 * 1024, 8192) == NULL,
            "missing medium master was accepted");
#ifdef WW_SPLICE_POOL_FAILURE_TEST
    MasterPoolItemCreateHandle original[3];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        original[i] = masters[i]->create_item_handle;
    for (unsigned int allocation = 1; allocation <= 4; ++allocation)
    {
        fail_allocation = allocation;
        require(
            bufferpoolCreate(
                masters[0], masters[1], masters[2], 2, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024, 1024 * 1024, 8192) ==
                NULL,
            "buffer-pool metadata allocation failure was not returned");
        require(fail_allocation == 0, "metadata allocation failure was not exercised");
        for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
            require(masters[i]->create_item_handle == original[i],
                    "failed buffer-pool construction published callbacks");
    }
#endif
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masterpoolDestroy(masters[i]);
#endif
}

static void testAllocationCharge(void)
{
    sbuf_t      *buffer   = sbufCreateSplice(33);
    const size_t expected = sizeof(sbuf_t) + 64 + SPLICE_BUFFER_STORAGE_SIZE + kSbufAllocationAlignment;
    require(sbufGetAllocationCharge(buffer) == expected, "unopened wrapper has wrong allocation charge");
    buffer->capacity = 64 + 1024 * 1024;
    buffer->len      = 1024 * 1024;
    require(sbufGetAllocationCharge(buffer) == expected, "logical body changed physical wrapper charge");
    buffer->len = 0;
    sbufDestroy(buffer);
}

int main(void)
{
    testCaseSet("buffer_pool_splice_test");
    testAllocationCharge();
    testConstructionFailure();
    testOrdinaryRecharge();
#if WW_HAVE_SPLICE
    testGlobalStateOwnership();
    testStartupLimits();
    testSharedReuseAndExhaustion();
    testBoundedLocalCache();
    testImmutablePadding();
    testRetirement();
    testDiscard();
    testConcurrentLeases();
    testTeardownRejectsActiveLease();
#else
    fixture_t fixture = makeFixture(1);
    require(bufferpoolGetSpliceBuffer(fixture.first) == NULL && errno == ENOSYS,
            "unsupported splice checkout did not return ENOSYS");
    destroyFixture(&fixture);
#endif
    return 0;
}
