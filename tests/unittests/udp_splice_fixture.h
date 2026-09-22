#pragma once
#include "splice_buffer.h"
#if WW_HAVE_SPLICE
/* Adapter fixtures retain their existing runtime/ownership harness. Inject a
 * short UDP write only after the real syscall has removed private-pipe bytes. */
static bool udp_test_short_splice;
static void (*udp_test_splice_observer)(void);
ssize_t __real_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags);
ssize_t __wrap_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags);
ssize_t __wrap_splice(int in, loff_t *off_in, int out, loff_t *off_out, size_t length, unsigned flags)
{
    if (udp_test_splice_observer != NULL)
        udp_test_splice_observer();
    if (udp_test_short_splice)
    {
        udp_test_short_splice = false;
        ssize_t moved         = __real_splice(in, off_in, out, off_out, length / 2, flags);
        twfRequire(moved > 0, "splice failure fixture must actually consume pipe bytes");
        return moved;
    }
    return __real_splice(in, off_in, out, off_out, length, flags);
}
static sbuf_t *udpTestSplicePayload(buffer_pool_t *pool)
{
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    twfRequire(buf != NULL, "allocate adapter splice fixture");
    static const char        body[]   = "pipe-backed datagram";
    splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
    twfRequire(write(metadata.pipefd[1], body, sizeof(body)) == sizeof(body), "populate adapter private pipe");
    buf->capacity = buf->l_pad + sizeof(body);
    sbufSetLength(buf, sizeof(body));
    return buf;
}
#endif
