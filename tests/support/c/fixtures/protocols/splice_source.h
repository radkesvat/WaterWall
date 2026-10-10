#pragma once

#include "splice_buffer.h"
#include "test_assert.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

/* Protocol ingress fixtures are independent of the managed destination inventory:
 * retaining or consuming these sources cannot refill an exhaustion scenario. */
static inline sbuf_t *testSpliceSourceBuffer(uint16_t padding, uint32_t minimum_capacity)
{
#if WW_HAVE_SPLICE
    int pair[2];
    TEST_REQUIRE(
        TEST_FAILURE_EXIT, pipe2(pair, O_NONBLOCK | O_CLOEXEC) == 0, "could not create unmanaged protocol-source pipe");
    int capacity = fcntl(pair[0], F_GETPIPE_SZ);
    if (capacity > 0 && (uint32_t) capacity < minimum_capacity)
        capacity = fcntl(pair[0], F_SETPIPE_SZ, (int) minimum_capacity);
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 capacity > 0 && (uint32_t) capacity >= minimum_capacity,
                 "unmanaged protocol-source pipe cannot hold the required fixture bytes");
    sbuf_t *buffer = sbufCreateSplice(padding);
    sbufSpliceSetMetadata(
        buffer, (splice_buffer_metadata_t) {.pipefd = {pair[0], pair[1]}, .pipe_capacity = (uint32_t) capacity});
    return buffer;
#else
    discard padding;
    discard minimum_capacity;
    return NULL;
#endif
}

/* Protocol fixtures may need a deliberately different prefix geometry. These
 * unmanaged inputs are independent of the production inventory and are closed
 * when released. Already populated inventory buffers need no setup. */
static inline int testSpliceSourceInitPipe(sbuf_t *buf)
{
#if WW_HAVE_SPLICE
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    if (metadata.pipefd[0] >= 0)
        return 0;
    assert(! sbufIsPooledSplice(buf));
    int pair[2];
    if (pipe2(pair, O_NONBLOCK | O_CLOEXEC) != 0)
        return -1;
    int capacity = fcntl(pair[0], F_GETPIPE_SZ);
    if (capacity > 0 && capacity < SPLICE_PAYLOAD_LIMIT)
        capacity = fcntl(pair[0], F_SETPIPE_SZ, SPLICE_PAYLOAD_LIMIT);
    if (capacity < 0)
    {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    sbufSpliceSetMetadata(
        buf, (splice_buffer_metadata_t) {.pipefd = {pair[0], pair[1]}, .pipe_capacity = (uint32_t) capacity});
    return 0;
#else
    discard buf;
    errno = ENOSYS;
    return -1;
#endif
}
