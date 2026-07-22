// Focused invariants for the nonblocking datagram write path (wioWriteDatagram):
//
//   - UDP sockets managed by the event loop are nonblocking.
//   - A datagram write carries an immutable explicit destination.
//   - EAGAIN/EINTR/ENOBUFS drop the datagram: return 0, recycle the buffer,
//     leave write_queue empty, and never register WW_WRITE.
//   - A dropped write to peer A can never be delivered to peer B later.
//   - A receive from peer C cannot redirect an explicit write.
//   - Generic wioWrite() on UDP delegates to the datagram path and never queues.
//   - TCP keeps the existing retry queue behavior.
//
// The send/sendto syscalls are wrapped with a deterministic failure seam
// (ld --wrap), so the transient errors are injected instead of relying on the
// host UDP send buffer to fill at a predictable point.

#include "buffer_pool.h"
#include "global_state.h"
#include "master_pool.h"
#include "threadsafe_generic_pool.h"
#include "wevent.h"
#include "wlibc.h"
#include "wloop.h"
#include "wsocket.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static int force_sendto_errno = 0;
static int force_send_errno   = 0;

extern ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr,
                             socklen_t addrlen);
extern ssize_t __real_send(int fd, const void *buf, size_t len, int flags);
ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags);

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen)
{
    if (force_sendto_errno != 0)
    {
        errno              = force_sendto_errno;
        force_sendto_errno = 0;
        return -1;
    }
    return __real_sendto(fd, buf, len, flags, addr, addrlen);
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
    if (force_send_errno != 0)
    {
        errno            = force_send_errno;
        force_send_errno = 0;
        return -1;
    }
    return __real_send(fd, buf, len, flags);
}

typedef struct udp_read_probe_s
{
    buffer_pool_t *pool;
    uint32_t       read_count;
    char           last_payload[64];
} udp_read_probe_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void onUdpRead(wio_t *io, sbuf_t *buf)
{
    udp_read_probe_t *probe = weventGetUserdata(io);
    uint32_t          len   = sbufGetLength(buf);

    require(len < sizeof(probe->last_payload), "probe payload too large");
    memoryCopy(probe->last_payload, sbufGetRawPtr(buf), len);
    probe->last_payload[len] = '\0';
    probe->read_count++;
    bufferpoolReuseBuffer(probe->pool, buf);
}

static sbuf_t *makePayload(buffer_pool_t *pool, const char *text)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    size_t  len = strlen(text);

    memoryCopy(sbufGetMutablePtr(buf), text, len);
    sbufSetLength(buf, (uint32_t) len);
    return buf;
}

static int makeBoundUdpSocket(sockaddr_u *addr_out)
{
    int fd = (int) socket(AF_INET, SOCK_DGRAM, 0);
    require(fd >= 0, "failed to create test UDP socket");

    sockaddr_u addr;
    memoryZero(&addr, sizeof(addr));
    require(sockaddrSetIpAddressPort(&addr, "127.0.0.1", 0) == 0, "failed to build loopback address");
    require(bind(fd, &addr.sa, sockaddrLen(&addr)) == 0, "failed to bind test UDP socket");
    require(nonBlocking(fd) == 0, "failed to set test UDP socket nonblocking");

    socklen_t addrlen = sizeof(*addr_out);
    memoryZero(addr_out, sizeof(*addr_out));
    require(getsockname(fd, &addr_out->sa, &addrlen) == 0, "failed to read test UDP socket address");
    return fd;
}

// Wait for one datagram and require its payload; retries because loopback
// delivery is asynchronous relative to this thread.
static void expectDatagram(int fd, const char *expected, const char *message)
{
    char buf[128];

    for (int attempt = 0; attempt < 500; ++attempt)
    {
        int n = (int) recvfrom(fd, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n >= 0)
        {
            buf[n] = '\0';
            require(strcmp(buf, expected) == 0, message);
            return;
        }
        require(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR, "unexpected recvfrom error");
        usleep(2000);
    }
    require(false, message);
}

static void expectNoDatagram(int fd, const char *message)
{
    char buf[128];

    usleep(30000);
    int n = (int) recvfrom(fd, buf, sizeof(buf) - 1, 0, NULL, NULL);
    require(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK), message);
}

static void requireDropped(wio_t *io, int result, const char *message)
{
    require(result == 0, message);
    require(wioGetWriteBufSize(io) == 0, "dropped datagram must not enter the write queue");
    require((wioGetEvents(io) & WW_WRITE) == 0, "dropped datagram must not register WW_WRITE");
}

static void runUdpChecks(wloop_t *loop, buffer_pool_t *pool, wio_t *io_udp)
{
    sockaddr_u addr_a, addr_b, addr_c;
    int        peer_a = makeBoundUdpSocket(&addr_a);
    int        peer_b = makeBoundUdpSocket(&addr_b);
    int        peer_c = makeBoundUdpSocket(&addr_c);

    // UDP event-loop sockets must be nonblocking.
    int fl = fcntl(wioGetFD(io_udp), F_GETFL);
    require(fl >= 0 && (fl & O_NONBLOCK) != 0, "event-loop UDP socket is not nonblocking");

    // Successful explicit send reaches only the addressed peer.
    require(wioWriteDatagram(io_udp, makePayload(pool, "alpha"), &addr_a) == 5,
            "explicit datagram send did not report full length");
    expectDatagram(peer_a, "alpha", "peer A did not receive the explicit datagram");
    expectNoDatagram(peer_b, "peer B received a datagram addressed to peer A");

    // A zero-length datagram is a legitimate send: it returns 0 (the buffer is
    // consumed, same as a drop) and must still reach the peer.
    require(wioWriteDatagram(io_udp, makePayload(pool, ""), &addr_a) == 0, "zero-length datagram send failed");
    expectDatagram(peer_a, "", "peer A did not receive the zero-length datagram");

    // EAGAIN, EINTR and ENOBUFS all drop: return 0, no queue, no WW_WRITE.
    force_sendto_errno = EAGAIN;
    requireDropped(io_udp,
                   wioWriteDatagram(io_udp, makePayload(pool, "drop-eagain"), &addr_a),
                   "EAGAIN did not drop the datagram");
    force_sendto_errno = EINTR;
    requireDropped(
        io_udp, wioWriteDatagram(io_udp, makePayload(pool, "drop-eintr"), &addr_a), "EINTR did not drop the datagram");
    force_sendto_errno = ENOBUFS;
    requireDropped(io_udp,
                   wioWriteDatagram(io_udp, makePayload(pool, "drop-enobufs"), &addr_a),
                   "ENOBUFS did not drop the datagram");
    require(wioGetError(io_udp) == 0, "transient drop must not set io->error");
    expectNoDatagram(peer_a, "a dropped datagram was delivered to peer A");

    // Destination isolation: a dropped write to A must never surface at B.
    force_sendto_errno = EAGAIN;
    requireDropped(
        io_udp, wioWriteDatagram(io_udp, makePayload(pool, "lost-for-a"), &addr_a), "isolation setup drop failed");
    require(wioWriteDatagram(io_udp, makePayload(pool, "bravo"), &addr_b) == 5, "follow-up datagram to peer B failed");
    expectDatagram(peer_b, "bravo", "peer B did not receive its own datagram");
    expectNoDatagram(peer_a, "peer A received a payload after its datagram was dropped");
    expectNoDatagram(peer_b, "peer B received the datagram that was dropped for peer A");

    // A receive from peer C (which rewrites io->peeraddr) cannot redirect an
    // explicit write.
    udp_read_probe_t probe;
    memoryZero(&probe, sizeof(probe));
    probe.pool = pool;
    weventSetUserData(io_udp, &probe);
    wioSetCallBackRead(io_udp, onUdpRead);
    require(wioRead(io_udp) == 0, "failed to start UDP read");

    sockaddr_u io_addr;
    socklen_t  io_addrlen = sizeof(io_addr);
    memoryZero(&io_addr, sizeof(io_addr));
    require(getsockname(wioGetFD(io_udp), &io_addr.sa, &io_addrlen) == 0, "failed to read io_udp address");
    require(sendto(peer_c, "ping", 4, 0, &io_addr.sa, sockaddrLen(&io_addr)) == 4, "peer C failed to send");
    require(wloopRun(loop) == 0, "event loop failed while receiving from peer C");
    require(probe.read_count == 1 && strcmp(probe.last_payload, "ping") == 0, "datagram from peer C was not received");

    require(wioWriteDatagram(io_udp, makePayload(pool, "charlie"), &addr_a) == 7,
            "explicit datagram send after receive failed");
    expectDatagram(peer_a, "charlie", "receive from peer C redirected an explicit write to peer A");
    expectNoDatagram(peer_c, "peer C received a datagram addressed to peer A");

    // Generic wioWrite() on UDP delegates to the datagram path: the default
    // peer is used, and a transient failure drops instead of queuing.
    wioSetPeerAddr(io_udp, &addr_a.sa, (int) sockaddrLen(&addr_a));
    force_sendto_errno = EAGAIN;
    requireDropped(io_udp,
                   wioWrite(io_udp, makePayload(pool, "drop-generic")),
                   "generic wioWrite queued a UDP datagram on EAGAIN");
    require(wioWrite(io_udp, makePayload(pool, "delta")) == 5, "generic wioWrite on UDP failed");
    expectDatagram(peer_a, "delta", "generic wioWrite did not use the default peer address");

    // Permanent errors report -1, set io->error, and leave the socket usable.
    force_sendto_errno = EMSGSIZE;
    require(wioWriteDatagram(io_udp, makePayload(pool, "too-big"), &addr_a) == -1,
            "permanent send error was not reported");
    require(wioGetError(io_udp) == EMSGSIZE, "permanent send error did not set io->error");
    require(wioIsOpened(io_udp), "permanent datagram error closed the UDP socket");
    require(wioWriteDatagram(io_udp, makePayload(pool, "echo"), &addr_a) == 4,
            "UDP socket unusable after a permanent send error");
    expectDatagram(peer_a, "echo", "peer A did not receive the datagram after a permanent error");

    closesocket(peer_a);
    closesocket(peer_b);
    closesocket(peer_c);
}

static void runTcpChecks(wloop_t *loop, buffer_pool_t *pool, const sockaddr_u *udp_addr)
{
    int listener = (int) socket(AF_INET, SOCK_STREAM, 0);
    require(listener >= 0, "failed to create TCP listener");

    sockaddr_u addr;
    memoryZero(&addr, sizeof(addr));
    require(sockaddrSetIpAddressPort(&addr, "127.0.0.1", 0) == 0, "failed to build TCP loopback address");
    require(bind(listener, &addr.sa, sockaddrLen(&addr)) == 0, "failed to bind TCP listener");
    require(listen(listener, 1) == 0, "failed to listen");

    socklen_t addrlen = sizeof(addr);
    require(getsockname(listener, &addr.sa, &addrlen) == 0, "failed to read TCP listener address");

    int client = (int) socket(AF_INET, SOCK_STREAM, 0);
    require(client >= 0, "failed to create TCP client");
    require(connect(client, &addr.sa, sockaddrLen(&addr)) == 0, "failed to connect TCP client");

    int server = (int) accept(listener, NULL, NULL);
    require(server >= 0, "failed to accept TCP connection");
    require(nonBlocking(client) == 0, "failed to set TCP client nonblocking");

    wio_t *io_tcp = wioGet(loop, server);
    require(io_tcp != NULL && wioGetType(io_tcp) == WIO_TYPE_TCP, "accepted socket was not typed as TCP");

    // The explicit-destination datagram API rejects stream sockets.
    require(wioWriteDatagram(io_tcp, makePayload(pool, "not-a-datagram"), udp_addr) == -1,
            "wioWriteDatagram accepted a TCP socket");
    require(wioIsOpened(io_tcp), "datagram-type rejection closed the TCP socket");

    // TCP regression: a retryable send still enqueues and flushes later.
    force_send_errno = EAGAIN;
    require(wioWrite(io_tcp, makePayload(pool, "hello")) == 0, "TCP EAGAIN write did not report 0");
    require(wioGetWriteBufSize(io_tcp) == 5, "TCP EAGAIN write was not queued");
    require((wioGetEvents(io_tcp) & WW_WRITE) != 0, "TCP EAGAIN write did not register WW_WRITE");
    require(wloopRun(loop) == 0, "event loop failed while flushing the TCP write queue");
    require(wioGetWriteBufSize(io_tcp) == 0, "TCP write queue did not flush");

    char received[16];
    for (int attempt = 0;; ++attempt)
    {
        int n = (int) recv(client, received, sizeof(received) - 1, 0);
        if (n >= 0)
        {
            received[n] = '\0';
            require(strcmp(received, "hello") == 0, "flushed TCP payload corrupted");
            break;
        }
        require(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR, "unexpected TCP recv error");
        require(attempt < 500, "flushed TCP payload never arrived");
        usleep(2000);
    }

    wioClose(io_tcp);
    closesocket(client);
    closesocket(listener);
}

int main(void)
{
    master_pool_t             *large_master = masterpoolCreateWithCapacity(16);
    master_pool_t             *small_master = masterpoolCreateWithCapacity(16);
    master_pool_t             *wio_master   = masterpoolCreateWithCapacity(16);
    buffer_pool_t             *buffer_pool  = bufferpoolCreate(large_master, small_master, 16, 8192, 1024);
    threadsafe_generic_pool_t *wio_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(wio_master, sizeof(wio_t), 16);
    threadsafe_generic_pool_t *wio_pools[] = {wio_pool};

    GSTATE.shortcut_wios_pools = wio_pools;
    tl_wid                     = 0;

    wloop_t *loop = wloopCreate(WLOOP_FLAG_RUN_ONCE, buffer_pool, 0);
    require(loop != NULL, "failed to create event loop");

    wio_t *io_udp = wloopCreateUdpServer(loop, "127.0.0.1", 0);
    require(io_udp != NULL, "failed to create event-loop UDP socket");

    sockaddr_u udp_addr;
    socklen_t  udp_addrlen = sizeof(udp_addr);
    memoryZero(&udp_addr, sizeof(udp_addr));
    require(getsockname(wioGetFD(io_udp), &udp_addr.sa, &udp_addrlen) == 0, "failed to read UDP io address");

    runUdpChecks(loop, buffer_pool, io_udp);
    runTcpChecks(loop, buffer_pool, &udp_addr);

    // A socket that cannot be switched to nonblocking must be rejected: the
    // io comes back closed instead of staying blocking on the event loop.
    int dead_fd = (int) socket(AF_INET, SOCK_DGRAM, 0);
    require(dead_fd >= 0, "failed to create throwaway socket");
    closesocket(dead_fd);
    wio_t *rejected = wioGet(loop, dead_fd);
    require(rejected != NULL && wioIsClosed(rejected), "failed socket init did not reject the io");

    wloopDestroy(&loop);
    GSTATE.shortcut_wios_pools = NULL;

    threadsafegenericpoolDestroy(wio_pool);
    bufferpoolDestroy(buffer_pool);

    masterpoolMakeEmpty(wio_master);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(wio_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    return 0;
}
