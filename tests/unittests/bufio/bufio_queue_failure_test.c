/*
 * Covers: Fatal BufferStream and ContextQueue allocation failure, queue geometry, and empty ContextQueue pops.
 * Setup: Real queues and buffer pools; the allocator backend rejects the next deque growth in forked children.
 * Checks: Insertion failure reaches abortProgramNow(1) without changing entry counts or stream bytes;
 * empty pops return NULL without changing the FIFO, including after wraparound and complete draining.
 * Limits: Allocation failure is injected below the shared fatal allocation gate.
 * CTest: waterwall.bufio_queue_failure_unit
 */
#include "buffer_queue.h"
#include "buffer_stream.h"
#include "context_queue.h"

#include "test_assert.h"

#include <sys/wait.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)

enum
{
    kExpectedAbort               = 73,
    kReturnedFromFailedInsertion = 74,
    kPayloadSize                 = 8192
};

static bool             fail_next_reallocation;
static unsigned         rejected_reallocations;
static buffer_stream_t *stream_probe;
static context_queue_t *context_probe;
static size_t           expected_entries;
static size_t           expected_bytes;

#if ALLOCATOR_BYPASS == 1
#define realReallocate      __real_realloc
#define wrapReallocate      __wrap_realloc
#define realOtherReallocate __real_mi_realloc
#define wrapOtherReallocate __wrap_mi_realloc
#else
#define realReallocate      __real_mi_realloc
#define wrapReallocate      __wrap_mi_realloc
#define realOtherReallocate __real_realloc
#define wrapOtherReallocate __wrap_realloc
#endif
void          *realReallocate(void *ptr, size_t size);
void          *wrapReallocate(void *ptr, size_t size);
void          *realOtherReallocate(void *ptr, size_t size);
void          *wrapOtherReallocate(void *ptr, size_t size);
_Noreturn void __wrap_abortProgramNow(int exit_code);

void *wrapOtherReallocate(void *ptr, size_t size)
{
    return realOtherReallocate(ptr, size);
}

void *wrapReallocate(void *ptr, size_t size)
{
    if (fail_next_reallocation)
    {
        fail_next_reallocation = false;
        ++rejected_reallocations;
        return NULL;
    }
    return realReallocate(ptr, size);
}

_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    require(exit_code == 1 && rejected_reallocations == 1 && ! fail_next_reallocation,
            "insertion did not abort for the injected growth failure");
    if (stream_probe != NULL)
    {
        require(stream_probe->size == expected_bytes &&
                    (size_t) bs_doublequeue_t_size(&stream_probe->q) == expected_entries,
                "failed stream insertion changed byte or entry accounting");
    }
    else
    {
        require(context_probe != NULL && contextqueueLen(context_probe) == expected_entries,
                "failed context insertion changed the queue");
    }
    _Exit(kExpectedAbort);
}

static sbuf_t *makeFullBuffer(buffer_pool_t *pool)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(buf, kPayloadSize);
    return buf;
}

static bool testStreamInsertionFailure(buffer_pool_t *pool)
{
    testCaseSet("buffer stream insertion failure");
    const pid_t child = fork();
    require(child >= 0, "failed to fork stream insertion child");
    if (child == 0)
    {
        buffer_stream_t stream = bufferstreamCreate(pool, 0);
        expected_entries       = (size_t) bs_doublequeue_t_capacity(&stream.q);
        for (size_t i = 0; i < expected_entries; ++i)
            bufferstreamPush(&stream, makeFullBuffer(pool));
        sbuf_t *incoming       = makeFullBuffer(pool);
        stream_probe           = &stream;
        expected_bytes         = stream.size;
        fail_next_reallocation = true;
        bufferstreamPush(&stream, incoming);
        _Exit(kReturnedFromFailedInsertion);
    }
    int status;
    require(waitpid(child, &status, 0) == child, "failed to wait for stream insertion child");
    return TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == kExpectedAbort,
                      "BufferStream did not reject failed growth before reporting insertion success");
}

static bool testContextInsertionFailure(void)
{
    testCaseSet("context queue insertion failure");
    const pid_t child = fork();
    require(child >= 0, "failed to fork context insertion child");
    if (child == 0)
    {
        context_queue_t queue = contextqueueCreate();
        expected_entries      = (size_t) ww_context_queue_t_capacity(&queue.q);
        context_t *contexts   = memoryCalloc(expected_entries + 1, sizeof(*contexts));
        require(contexts != NULL, "failed to allocate context queue test entries");
        for (size_t i = 0; i < expected_entries; ++i)
            contextqueuePush(&queue, &contexts[i]);
        context_probe          = &queue;
        fail_next_reallocation = true;
        contextqueuePush(&queue, &contexts[expected_entries]);
        _Exit(kReturnedFromFailedInsertion);
    }
    int status;
    require(waitpid(child, &status, 0) == child, "failed to wait for context insertion child");
    return TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == kExpectedAbort,
                      "ContextQueue silently accepted a failed insertion");
}

static bool testEmptyContextPop(void)
{
    testCaseSet("context queue empty pop");
    const pid_t child = fork();
    require(child >= 0, "failed to fork empty context pop child");
    if (child == 0)
    {
        context_queue_t queue       = contextqueueCreate();
        context_t       contexts[2] = {0};
        require(contextqueuePop(&queue) == NULL && contextqueueLen(&queue) == 0,
                "fresh empty queue pop changed the queue or returned a context");
        const size_t capacity = (size_t) ww_context_queue_t_capacity(&queue.q);
        for (size_t i = 0; i <= capacity; ++i)
        {
            contextqueuePush(&queue, &contexts[0]);
            contextqueuePush(&queue, &contexts[1]);
            require(contextqueuePop(&queue) == &contexts[0] && contextqueuePop(&queue) == &contexts[1],
                    "context queue changed FIFO order after an empty pop");
            require(contextqueuePop(&queue) == NULL && contextqueuePop(&queue) == NULL && contextqueueLen(&queue) == 0,
                    "drained queue pop changed the queue or returned a stale context");
        }
        contextqueueDestroy(&queue);
        _Exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child, "failed to wait for empty context pop child");
    return TEST_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                      "ContextQueue empty pop did not preserve its documented FIFO contract");
}

static bool testQueueGeometryRejection(void)
{
    testCaseSet("buffer queue geometry rejection");
    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    /* This many entries fit before STC adds an empty slot and rounds its ring;
     * the real pointer array would exceed the container's signed byte range. */
    const size_t excessive_entries = (size_t) PTRDIFF_MAX / sizeof(sbuf_t *);
    const bool   rejected          = ! bufferqueueReserveExtra(&queue, excessive_entries) &&
                          ! bufferqueueReserveExtra(&queue, SIZE_MAX) && queue.q.cbuf == NULL &&
                          bufferqueueGetBufCount(&queue) == 0;
    const bool accepted = bufferqueueInit(&queue, 2) && ww_sbuffer_queue_t_capacity(&queue.q) >= 2;
    bufferqueueDestroy(&queue);
    return TEST_CHECK(rejected && accepted, "queue geometry refusal changed storage or rejected valid capacity");
}

int main(void)
{
    testCaseSet("bufio queue failure fixture");
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masters[i] = masterpoolCreateWithCapacity(4);
        require(masters[i] != NULL, "failed to create buffer master pool");
    }
    buffer_pool_t *pool =
        bufferpoolCreate(masters[0], masters[1], masters[2], 2, kPayloadSize, 4096, 1024, kPayloadSize, kPayloadSize);
    require(pool != NULL, "failed to create buffer pool");

    bool passed = testStreamInsertionFailure(pool);
    passed      = testContextInsertionFailure() && passed;
    passed      = testEmptyContextPop() && passed;
    passed      = testQueueGeometryRejection() && passed;

    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
    return passed ? 0 : 1;
}
