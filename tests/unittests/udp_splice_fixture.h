#pragma once
#include "splice_buffer.h"
#include "udp_send.h"
#if defined(OS_LINUX)
/* Exercise owner cleanup independently of the sender's current implementation. */
static bool udp_test_retire_send;
static void (*udp_test_send_observer)(void);
udp_send_result_t __real_udpSendBuffer(int fd, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr);
udp_send_result_t __wrap_udpSendBuffer(int fd, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr);
udp_send_result_t __wrap_udpSendBuffer(int fd, sbuf_t *buf, const sockaddr_u *peer, bool retry_eintr)
{
    if (udp_test_send_observer != NULL)
        udp_test_send_observer();
    if (udp_test_retire_send)
    {
        udp_test_retire_send = false;
        return (udp_send_result_t) {.bytes = -1, .error = EIO, .retire = true};
    }
    return __real_udpSendBuffer(fd, buf, peer, retry_eintr);
}
#endif

#if WW_HAVE_SPLICE
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
