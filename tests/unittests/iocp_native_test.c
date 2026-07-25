// Native IOCP backend correctness tests (Windows-only, EVENT_IOCP).
//
// These exercise the invariants from iocp-implementation-plan.md that the wepoll
// default backend cannot cover:
//   * a read/accept callback that closes its socket synchronously is safe;
//   * closing a listener from the first accept callback drains the other posted
//     AcceptEx records (their cancellation completions) without callbacks;
//   * destroying a loop with operations still posted drains the kernel before
//     freeing memory;
//   * read-stop suppresses a receive that IOCP already dequeued;
//   * ConnectEx and callback-driven wioFree keep the pending cursor valid;
//   * TCP writes use one active WSASend and preserve queued data across callbacks;
//   * per-IO and loop-wide operation accounting returns to a clean baseline.
//
// The test only builds/runs when the native IOCP backend is selected
// (windows-iocp preset). Under any other backend it is an empty success so the
// same CMake wiring is harmless.

#include "wlibc.h"

#if ! defined(EVENT_IOCP)
int main(void)
{
    // Native IOCP not selected: nothing to test.
    return 0;
}
#else

#include "buffer_pool.h"
#include "global_state.h"
#include "iowatcher.h"
#include "master_pool.h"
#include "threadsafe_generic_pool.h"
#include "wevent.h"
#include "wloop.h"
#include "worker.h"
#include "wsocket.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

// ---------------------------------------------------------------------------
// Shared pool scaffolding (mirrors the other event-loop unit tests).
// ---------------------------------------------------------------------------

typedef struct env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *wio_master;
    buffer_pool_t             *buffer_pool;
    threadsafe_generic_pool_t *wio_pool;
    threadsafe_generic_pool_t *wio_pools[1];
} env_t;

static void envSetup(env_t *env)
{
    env->large_master = masterpoolCreateWithCapacity(64);
    env->small_master = masterpoolCreateWithCapacity(64);
    env->wio_master   = masterpoolCreateWithCapacity(64);
    env->buffer_pool  = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 1024);
    env->wio_pool     = threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wio_master, sizeof(wio_t), 64);
    env->wio_pools[0] = env->wio_pool;

    GSTATE.shortcut_wios_pools = env->wio_pools;
    tl_wid                     = 0;
}

static void envTeardown(env_t *env)
{
    GSTATE.shortcut_wios_pools = NULL;
    threadsafegenericpoolDestroy(env->wio_pool);
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->wio_master);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->wio_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

// Drive the loop until loop-wide live operations settle to `target` (or give up).
static bool pumpUntilLiveOperations(wloop_t *loop, uint32_t target, int max_iterations)
{
    for (int i = 0; i < max_iterations; ++i)
    {
        if (wloopGetIocpLiveOperations(loop) == target)
        {
            return true;
        }
        wloopProcessEvents(loop, 10);
    }
    return wloopGetIocpLiveOperations(loop) == target;
}

static uint16_t boundPort(wio_t *server)
{
    sockaddr_u addr;
    socklen_t  len = sizeof(addr);
    memoryZero(&addr, sizeof(addr));
    require(getsockname(wioGetFD(server), &addr.sa, &len) == 0, "getsockname on listener failed");
    return sockaddrPort(&addr);
}

static SOCKET connectClient(uint16_t port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(s != INVALID_SOCKET, "client socket() failed");

    struct sockaddr_in sin;
    memoryZero(&sin, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(port);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(connect(s, (struct sockaddr *) &sin, sizeof(sin)) == 0, "client connect() failed");

    DWORD tmo = 2000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmo, sizeof(tmo));
    return s;
}

static sbuf_t *makeFilledBuffer(buffer_pool_t *pool, char value, uint32_t len)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    require(len <= sbufGetMaximumWriteableSize(buf), "test payload exceeds the large-buffer capacity");
    memorySet(sbufGetMutablePtr(buf), value, len);
    sbufSetLength(buf, len);
    return buf;
}

static void setSocketNonblocking(SOCKET socket)
{
    u_long enabled = 1;
    require(ioctlsocket(socket, FIONBIO, &enabled) == 0, "ioctlsocket(FIONBIO) failed");
}

// ---------------------------------------------------------------------------
// Test 1: IPv4 accept + echo round trip, then a clean baseline.
// ---------------------------------------------------------------------------

typedef struct echo_state_s
{
    int accepted;
    int closed;
} echo_state_t;

static void echoRead(wio_t *io, sbuf_t *buf)
{
    // read_cb owns buf; wioWrite consumes it (echoes it straight back). The
    // receive is auto-reposted by the backend because read stays enabled.
    wioWrite(io, buf);
}

static void echoConnClose(wio_t *io)
{
    echo_state_t *st = weventGetUserdata(io);
    if (st != NULL)
    {
        st->closed++;
    }
}

static void echoAccept(wio_t *connio)
{
    echo_state_t *st = weventGetUserdata(connio);
    require(st != NULL, "accepted io lost its inherited userdata");
    st->accepted++;
    wioSetCallBackRead(connio, echoRead);
    wioSetCallBackClose(connio, echoConnClose);
    wioRead(connio);
}

static void testEchoRoundTrip(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    echo_state_t st     = {0};
    wio_t       *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, echoAccept);
    require(server != NULL, "tcp server create failed");
    weventSetUserData(server, &st);

    require(wloopGetIocpPostedOperations(loop) >= 1, "listener posted no AcceptEx records");

    uint16_t port   = boundPort(server);
    SOCKET   client = connectClient(port);

    const char *msg = "hello-iocp";
    require(send(client, msg, (int) strlen(msg), 0) == (int) strlen(msg), "client send failed");

    // Pump the loop so AcceptEx -> WSARecv -> echo WSASend complete.
    char received[64] = {0};
    int  got          = -1;
    for (int i = 0; i < 200 && got <= 0; ++i)
    {
        wloopProcessEvents(loop, 10);
        got = recv(client, received, sizeof(received) - 1, 0);
        if (got == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
        {
            got = 0;
        }
    }
    require(got == (int) strlen(msg), "did not receive the echoed payload");
    received[got] = '\0';
    require(strcmp(received, msg) == 0, "echoed payload mismatched");
    require(st.accepted == 1, "accept callback did not run exactly once");

    // Close the client; the server sees EOF and closes the accepted connection.
    closesocket(client);
    for (int i = 0; i < 200 && st.closed == 0; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.closed == 1, "server did not close the accepted connection on EOF");

    // Close the listener and drain its outstanding AcceptEx cancellations.
    wioClose(server);
    require(pumpUntilLiveOperations(loop, 0, 500), "loop-wide live operations did not drain to zero");
    require(wloopGetIocpPostedOperations(loop) == 0, "posted operations did not drain to zero");

    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 2: closing the listener from the first accept callback drains the rest.
// ---------------------------------------------------------------------------

typedef struct closer_state_s
{
    wio_t *server;
    int    accepted;
} closer_state_t;

static void closingAccept(wio_t *connio)
{
    closer_state_t *st = weventGetUserdata(connio);
    require(st != NULL, "accepted io lost its inherited userdata");
    st->accepted++;
    // Re-entrant close of both the accepted socket and the listener from inside
    // the accept callback. The other posted AcceptEx records must drain safely.
    wioClose(connio);
    wioClose(st->server);
}

static void testCloseListenerFromAccept(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    closer_state_t st     = {0};
    wio_t         *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, closingAccept);
    require(server != NULL, "tcp server create failed");
    st.server = server;
    weventSetUserData(server, &st);

    uint16_t port   = boundPort(server);
    SOCKET   client = connectClient(port);

    require(pumpUntilLiveOperations(loop, 0, 500),
            "closing the listener from accept_cb did not drain all AcceptEx records");
    require(st.accepted == 1, "accept callback ran more than once after listener close");
    require(wioGetIocpLiveRecords(server) == 0, "listener still holds live records after drain");

    closesocket(client);
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 3: a read callback that closes its socket synchronously is safe.
// ---------------------------------------------------------------------------

typedef struct rclose_state_s
{
    int reads;
    int closed;
} rclose_state_t;

static void readThenClose(wio_t *io, sbuf_t *buf)
{
    rclose_state_t *st = weventGetUserdata(io);
    st->reads++;
    bufferpoolReuseBuffer(io->loop->bufpool, buf); // consume the buffer once
    wioClose(io);                                  // re-entrant close from read_cb
}

static void readCloseConnClose(wio_t *io)
{
    rclose_state_t *st = weventGetUserdata(io);
    st->closed++;
}

static void readCloseAccept(wio_t *connio)
{
    (void) weventGetUserdata(connio);
    wioSetCallBackRead(connio, readThenClose);
    wioSetCallBackClose(connio, readCloseConnClose);
    wioRead(connio);
}

static void testReadCallbackCloses(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    rclose_state_t st     = {0};
    wio_t         *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, readCloseAccept);
    require(server != NULL, "tcp server create failed");
    weventSetUserData(server, &st);

    uint16_t    port   = boundPort(server);
    SOCKET      client = connectClient(port);
    const char *msg    = "x";
    require(send(client, msg, 1, 0) == 1, "client send failed");

    for (int i = 0; i < 200 && st.closed == 0; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.reads == 1, "read callback did not run exactly once");
    require(st.closed == 1, "connection was not closed exactly once from read_cb");

    wioClose(server);
    require(pumpUntilLiveOperations(loop, 0, 500), "live operations did not drain after read-close");

    closesocket(client);
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 4: read-stop suppresses a receive that IOCP already dequeued, and a later
// read-start posts a fresh receive.
// ---------------------------------------------------------------------------

typedef struct read_stop_state_s
{
    wio_t *conn;
    int    reads;
    char   byte;
} read_stop_state_t;

static void readStopRead(wio_t *io, sbuf_t *buf)
{
    read_stop_state_t *st = weventGetUserdata(io);
    st->reads++;
    st->byte = *(const char *) sbufGetRawPtr(buf);
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    wioReadStop(io);
}

static void readStopAccept(wio_t *connio)
{
    read_stop_state_t *st = weventGetUserdata(connio);
    require(st->conn == NULL, "read-stop test accepted more than one connection");
    st->conn = connio;
    wioSetCallBackRead(connio, readStopRead);
    require(wioRead(connio) == 0, "failed to post read-stop test receive");
}

static void testReadStopAfterDequeue(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    read_stop_state_t st     = {0};
    wio_t            *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, readStopAccept);
    require(server != NULL, "tcp server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "read-stop test connection was not accepted");

    require(send(client, "a", 1, 0) == 1, "failed to send the suppressed receive");
    for (int i = 0; i < 200 && st.conn->iocp_completed_head == NULL; ++i)
    {
        require(iowatcherPollEvents(loop, 10) >= 0, "IOCP poll failed while dequeuing the stopped receive");
    }
    require(st.conn->iocp_completed_head != NULL, "receive completion was not dequeued for read-stop race");
    require(st.conn->pending, "dequeued receive was not linked into the generic pending list");

    // This is the exact poll-to-pending window in the finding: IOCP has removed
    // the record from the posted list, but its user callback has not run.
    require(wioReadStop(st.conn) == 0, "read-stop failed after dequeue");
    require(st.reads == 0, "read callback ran after read-stop");
    require(st.conn->iocp_completed_head == NULL, "stopped dequeued receive was stranded");
    require(wioGetIocpLiveRecords(st.conn) == 0, "stopped dequeued receive record was not retired");
    require(wioIsOpened(st.conn), "read-stop closed the connection");
    require(st.conn->pending, "read-stop released a still-linked generic pending node");

    require(wioReadStart(st.conn) == 0, "read restart failed");
    require(send(client, "b", 1, 0) == 1, "failed to send after read restart");
    for (int i = 0; i < 200 && st.conn->iocp_completed_head == NULL; ++i)
    {
        require(iowatcherPollEvents(loop, 10) >= 0, "IOCP poll failed after read restart");
    }
    require(st.conn->iocp_completed_head != NULL, "restarted receive completion was not dequeued");
    require(st.conn->pending, "restarted receive lost the existing pending-list reference");
    require(st.conn->pending_next != (wevent_t *) st.conn, "read restart created a self-linked pending node");

    for (int i = 0; i < 200 && st.reads == 0; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.reads == 1 && st.byte == 'b', "restarted read did not receive the fresh payload");

    wioClose(st.conn);
    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "read-stop test operations did not drain");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 5: pending membership prevents pool reuse, zero-record free detaches the
// descriptor table, and a close callback may free synchronously.
// ---------------------------------------------------------------------------

typedef struct pending_free_state_s
{
    int closes;
} pending_free_state_t;

static void closeThenFree(wio_t *io)
{
    pending_free_state_t *st = weventGetUserdata(io);
    st->closes++;
    wioFree(io);
}

static void testPendingFreeAndDescriptorReuse(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "pending-free loop create failed");

    wio_t *old_io = wioCreateSocket(loop, "127.0.0.1", 0, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
    require(old_io != NULL, "pending-free socket create failed");
    int old_fd = wioGetFD(old_io);

    // Model an IOCP completion already linked into loop->pendings but with its
    // operation record retired. The list node itself must keep old_io out of the
    // pool until wloopProcessPendings consumes it.
    EVENT_PENDING(old_io);
    require(wioGetIocpLiveRecords(old_io) == 0, "pending-free test unexpectedly has a live IOCP record");
    wioFree(old_io);
    require(loop->ios.ptr[old_fd] == NULL, "zero-record wioFree left the descriptor-table entry attached");
    require(old_io->pending, "wioFree cleared a still-linked pending-list node");
    require(old_io->iocp_deferred_finalize, "pending wioFree was not deferred");

    wio_t *reused = NULL;
    for (int attempt = 0; attempt < 512; ++attempt)
    {
        wio_t *candidate = wioCreateSocket(loop, "127.0.0.1", 0, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
        require(candidate != NULL, "pending-free descriptor-reuse candidate failed");
        int candidate_fd = wioGetFD(candidate);
        require(candidate != old_io, "pending-list-referenced wio_t was returned to the pool");
        if (candidate_fd == old_fd)
        {
            reused = candidate;
            break;
        }
        wioFree(candidate);
        require(loop->ios.ptr[candidate_fd] == NULL, "zero-record candidate remained in the descriptor table");
    }
    require(reused != NULL, "pending-free test could not exercise numeric descriptor reuse");

    // Consuming the pending node releases old_io's final lifetime reference.
    require(wloopProcessEvents(loop, 0) >= 0, "pending-free pending pass failed");
    require(loop->npendings == 0, "pending-free pending node was not consumed");

    int reused_fd = wioGetFD(reused);
    wioFree(reused);
    require(loop->ios.ptr[reused_fd] == NULL, "reused descriptor remained attached after wioFree");

    // Direct wioClose invokes the callback after its own final access to io, so
    // callback-driven wioFree may finalize immediately without invalidating the
    // outer close dispatch.
    pending_free_state_t st       = {0};
    wio_t               *close_io = wioCreateSocket(loop, "127.0.0.1", 0, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
    require(close_io != NULL, "close-callback-free socket create failed");
    int close_fd = wioGetFD(close_io);
    weventSetUserData(close_io, &st);
    wioSetCallBackClose(close_io, closeThenFree);
    require(wioClose(close_io) == 0, "direct close with freeing callback failed");
    require(st.closes == 1, "freeing close callback did not run exactly once");
    require(loop->ios.ptr[close_fd] == NULL, "freeing close callback left a descriptor-table reference");

    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 6: ConnectEx callback can wioFree its io, and descriptor reuse receives a
// distinct wio_t while the popped connect record is still live.
// ---------------------------------------------------------------------------

typedef struct connect_free_state_s
{
    wloop_t    *loop;
    const char *host;
    int         connected;
    int         closed;
    int         accepted;
    bool        descriptor_reused;
} connect_free_state_t;

static void connectFreeAccept(wio_t *connio)
{
    connect_free_state_t *st = weventGetUserdata(connio);
    st->accepted++;
    wioClose(connio);
}

static void connectFreeClose(wio_t *io)
{
    connect_free_state_t *st = weventGetUserdata(io);
    st->closed++;
}

static void connectThenFree(wio_t *io)
{
    connect_free_state_t *st     = weventGetUserdata(io);
    int                   old_fd = wioGetFD(io);
    uint32_t              old_id = wioGetID(io);
    wio_t                *old_io = io;
    st->connected++;

    // The connect record must remain live across this call so old_io cannot
    // return to the pool while the dispatcher and pending loop still hold it.
    wioFree(io);

    for (int attempt = 0; attempt < 512; ++attempt)
    {
        wio_t *candidate = wioCreateSocket(st->loop, st->host, 0, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
        require(candidate != NULL, "failed to create descriptor-reuse candidate");
        if (wioGetFD(candidate) == old_fd)
        {
            require(candidate != old_io, "descriptor reuse reinitialized the callback's live wio_t");
            require(wioGetID(candidate) != old_id, "descriptor reuse kept the stale wio generation");
            st->descriptor_reused = true;
            wioFree(candidate);
            break;
        }
        wioFree(candidate);
    }
}

static bool testConnectFreeFamily(env_t *env, const char *host, bool optional)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    connect_free_state_t st     = {.loop = loop, .host = host};
    wio_t               *server = wloopCreateTcpServer(loop, host, 0, connectFreeAccept);
    if (server == NULL && optional)
    {
        wloopDestroy(&loop);
        return false;
    }
    require(server != NULL, "ConnectEx test server create failed");
    weventSetUserData(server, &st);

    wio_t *client = wloopCreateTcpClient(loop, host, boundPort(server), connectThenFree, connectFreeClose);
    require(client != NULL, "wioConnect/ConnectEx client create failed");
    weventSetUserData(client, &st);

    for (int i = 0; i < 500 && (st.connected == 0 || st.accepted == 0); ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.connected == 1, "ConnectEx callback did not run exactly once");
    require(st.closed == 1, "connect callback wioFree did not close exactly once");
    require(st.accepted == 1, "ConnectEx connection was not accepted exactly once");
    require(st.descriptor_reused, "could not exercise numeric descriptor reuse");

    wioClose(server);
    require(pumpUntilLiveOperations(loop, 0, 500), "ConnectEx test operations did not drain");
    wloopDestroy(&loop);
    return true;
}

static void testConnectCallbackFreeAndFamilies(env_t *env)
{
    require(testConnectFreeFamily(env, "127.0.0.1", false), "IPv4 ConnectEx test unexpectedly skipped");
    if (! testConnectFreeFamily(env, "::1", true))
    {
        printf("iocp_native_test: IPv6 loopback unavailable, skipping IPv6 ConnectEx case\n");
    }
}

// ---------------------------------------------------------------------------
// Test 7: force the TCP send into WSASend, enqueue more writes from write_cb,
// and require the entire serialized stream to arrive.
// ---------------------------------------------------------------------------

#define SEND_TEST_CHUNK_SIZE         8192U
#define SEND_TEST_FOLLOWUPS          8
#define SEND_TEST_BACKPRESSURE_BYTES (4U * 1024U * 1024U)

typedef struct send_queue_state_s
{
    buffer_pool_t *pool;
    wio_t         *conn;
    size_t         initial_bytes;
    size_t         expected_bytes;
    int            write_callbacks;
    bool           followups_enqueued;
} send_queue_state_t;

static void sendQueueWrite(wio_t *io)
{
    send_queue_state_t *st = weventGetUserdata(io);
    st->write_callbacks++;
    if (st->followups_enqueued)
    {
        return;
    }

    st->followups_enqueued = true;
    for (int i = 0; i < SEND_TEST_FOLLOWUPS; ++i)
    {
        int nwrite = wioWrite(io, makeFilledBuffer(st->pool, 'B', SEND_TEST_CHUNK_SIZE));
        require(nwrite >= 0, "write callback failed to enqueue a follow-up send");
        st->expected_bytes += SEND_TEST_CHUNK_SIZE;
    }
}

static void sendQueueAccept(wio_t *connio)
{
    send_queue_state_t *st = weventGetUserdata(connio);
    require(st->conn == NULL, "send-queue test accepted more than one connection");
    st->conn = connio;

    int send_buffer_size = 1024;
    require(setsockopt(
                wioGetFD(connio), SOL_SOCKET, SO_SNDBUF, (const char *) &send_buffer_size, sizeof(send_buffer_size)) ==
                0,
            "failed to reduce the server send buffer");
}

static size_t forceQueuedSend(wio_t *conn, buffer_pool_t *pool, char value, size_t minimum_pending)
{
    size_t expected_bytes = 0;
    for (int i = 0; i < 4096; ++i)
    {
        int nwrite = wioWrite(conn, makeFilledBuffer(pool, value, SEND_TEST_CHUNK_SIZE));
        require(nwrite >= 0, "failed while forcing queued IOCP send");
        expected_bytes += SEND_TEST_CHUNK_SIZE;
        if (conn->iocp_send_active != NULL && ! write_queue_empty(&conn->write_queue) &&
            wioGetWriteBufSize(conn) >= minimum_pending)
        {
            break;
        }
    }
    require(conn->iocp_send_active != NULL, "test did not force the TCP path into WSASend");
    require(! write_queue_empty(&conn->write_queue), "test did not leave a buffer behind the active WSASend");
    require(wioGetWriteBufSize(conn) >= minimum_pending, "test did not create enough pending send backpressure");
    return expected_bytes;
}

static void testSerializedSendQueue(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    send_queue_state_t st     = {.pool = env->buffer_pool};
    wio_t             *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, sendQueueAccept);
    require(server != NULL, "send-queue server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "send-queue test connection was not accepted");

    // Do not read yet. Repeated full-size writes and a tiny SO_SNDBUF force the
    // first active overlapped send without relying on the small echo fast path.
    for (int i = 0; i < 4096 && st.conn->iocp_send_active == NULL; ++i)
    {
        int nwrite = wioWrite(st.conn, makeFilledBuffer(env->buffer_pool, 'A', SEND_TEST_CHUNK_SIZE));
        require(nwrite >= 0, "failed while forcing an overlapped send");
        st.initial_bytes += SEND_TEST_CHUNK_SIZE;
    }
    require(st.conn->iocp_send_active != NULL, "test did not force the TCP path into WSASend");
    st.expected_bytes = st.initial_bytes;
    wioSetCallBackWrite(st.conn, sendQueueWrite);
    setSocketNonblocking(client);

    size_t received_bytes = 0;
    char   received[16384];
    for (int attempt = 0; attempt < 20000 && (! st.followups_enqueued || received_bytes < st.expected_bytes ||
                                              wioGetWriteBufSize(st.conn) != 0);
         ++attempt)
    {
        wloopProcessEvents(loop, 1);
        for (;;)
        {
            int nread = recv(client, received, sizeof(received), 0);
            if (nread > 0)
            {
                for (int i = 0; i < nread; ++i)
                {
                    char expected = received_bytes + (size_t) i < st.initial_bytes ? 'A' : 'B';
                    require(received[i] == expected, "serialized send stream was reordered or corrupted");
                }
                received_bytes += (size_t) nread;
                continue;
            }
            if (nread == 0)
            {
                require(false, "send-queue peer closed before the stream completed");
            }
            int err = WSAGetLastError();
            require(err == WSAEWOULDBLOCK, "unexpected recv error in send-queue test");
            break;
        }
    }

    require(st.followups_enqueued, "overlapped send completion did not invoke write_cb");
    require(st.write_callbacks >= 1, "send completion callback did not run");
    require(received_bytes == st.expected_bytes, "queued send data was lost");
    require(wioGetWriteBufSize(st.conn) == 0, "serialized send queue did not drain");
    require(st.conn->iocp_send_active == NULL, "active send record survived queue drain");
    require((wioGetEvents(st.conn) & WW_WRITE) == 0, "write interest remained after the send queue drained");

    wioClose(st.conn);
    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "send-queue test operations did not drain");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 8: graceful close drains active/queued sends and accepts callback writes
// while the deferral is armed.
// ---------------------------------------------------------------------------

typedef struct close_drain_state_s
{
    buffer_pool_t *pool;
    wio_t         *conn;
    size_t         initial_bytes;
    size_t         expected_bytes;
    int            write_callbacks;
    int            closes;
    bool           followup_enqueued;
} close_drain_state_t;

static void closeDrainWrite(wio_t *io)
{
    close_drain_state_t *st = weventGetUserdata(io);
    st->write_callbacks++;
    if (st->followup_enqueued)
    {
        return;
    }

    require(io->close == 1 && io->close_timer != NULL,
            "close-drain write callback did not run during an armed deferral");
    st->followup_enqueued = true;
    for (int i = 0; i < SEND_TEST_FOLLOWUPS; ++i)
    {
        int nwrite = wioWrite(io, makeFilledBuffer(st->pool, 'B', SEND_TEST_CHUNK_SIZE));
        require(nwrite >= 0, "close-drain write callback failed to extend the deferred send stream");
        st->expected_bytes += SEND_TEST_CHUNK_SIZE;
    }
}

static void closeDrainClose(wio_t *io)
{
    close_drain_state_t *st = weventGetUserdata(io);
    st->closes++;
}

static void closeDrainAccept(wio_t *connio)
{
    close_drain_state_t *st = weventGetUserdata(connio);
    require(st->conn == NULL, "close-drain test accepted more than one connection");
    st->conn = connio;
    wioSetCallBackClose(connio, closeDrainClose);

    int send_buffer_size = 1024;
    require(setsockopt(
                wioGetFD(connio), SOL_SOCKET, SO_SNDBUF, (const char *) &send_buffer_size, sizeof(send_buffer_size)) ==
                0,
            "failed to reduce the close-drain send buffer");
}

static void testCloseDrainsWriteQueue(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "close-drain loop create failed");

    close_drain_state_t st     = {.pool = env->buffer_pool};
    wio_t              *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, closeDrainAccept);
    require(server != NULL, "close-drain server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "close-drain connection was not accepted");

    st.initial_bytes  = forceQueuedSend(st.conn, env->buffer_pool, 'A', SEND_TEST_CHUNK_SIZE);
    st.expected_bytes = st.initial_bytes;
    wioSetCallBackWrite(st.conn, closeDrainWrite);
    require(wioClose(st.conn) == 0, "close-drain wioClose failed");
    require(st.conn->close == 1, "queued graceful close was not marked deferred");
    require(st.conn->closed == 0, "queued graceful close marked the io closed before draining");
    require(wioIsOpened(st.conn), "queued graceful close made the io unavailable during drain");
    require(st.closes == 0, "queued graceful close callback fired before draining");
    require(! write_queue_empty(&st.conn->write_queue), "queued graceful close discarded the software write queue");
    require(st.conn->close_timer != NULL, "queued graceful close did not arm its timeout");

    setSocketNonblocking(client);
    size_t received_bytes = 0;
    char   received[16384];
    for (int attempt = 0;
         attempt < 20000 && (! st.followup_enqueued || received_bytes < st.expected_bytes || st.closes == 0);
         ++attempt)
    {
        wloopProcessEvents(loop, 1);
        for (;;)
        {
            int nread = recv(client, received, sizeof(received), 0);
            if (nread > 0)
            {
                for (int i = 0; i < nread; ++i)
                {
                    char expected = received_bytes + (size_t) i < st.initial_bytes ? 'A' : 'B';
                    require(received[i] == expected, "graceful close reordered or corrupted callback-extended bytes");
                }
                received_bytes += (size_t) nread;
                require(received_bytes <= st.expected_bytes, "graceful close delivered more bytes than were written");
                continue;
            }
            if (nread == 0)
            {
                require(received_bytes == st.expected_bytes, "peer closed before the graceful send stream drained");
                break;
            }
            int err = WSAGetLastError();
            require(err == WSAEWOULDBLOCK ||
                        (received_bytes == st.expected_bytes && (err == WSAECONNRESET || err == WSAESHUTDOWN)),
                    "unexpected recv error while draining the graceful close");
            break;
        }
    }

    require(st.followup_enqueued, "write callback did not extend the armed graceful-close deferral");
    require(st.write_callbacks >= 1, "graceful-close send completion did not invoke write_cb");
    require(received_bytes == st.expected_bytes, "graceful close lost queued or callback-enqueued data");
    require(st.closes == 1, "graceful close callback did not run exactly once after drain");
    require(wioIsClosed(st.conn), "graceful close did not close after the send stream drained");
    require(st.conn->close_timer == NULL, "graceful close left its close timer armed");

    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "close-drain operations did not return to baseline");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 9: an unread peer eventually forces a deferred close through its timer.
// ---------------------------------------------------------------------------

static void testCloseTimeoutForcesClose(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "close-timeout loop create failed");

    close_drain_state_t st     = {0};
    wio_t              *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, closeDrainAccept);
    require(server != NULL, "close-timeout server create failed");
    weventSetUserData(server, &st);

    SOCKET client              = connectClient(boundPort(server));
    int    receive_buffer_size = 1024;
    require(setsockopt(
                client, SOL_SOCKET, SO_RCVBUF, (const char *) &receive_buffer_size, sizeof(receive_buffer_size)) == 0,
            "failed to reduce the close-timeout receive buffer");
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "close-timeout connection was not accepted");

    (void) forceQueuedSend(st.conn, env->buffer_pool, 'T', SEND_TEST_BACKPRESSURE_BYTES);
    wioSetCloseTimeout(st.conn, 200);
    require(wioClose(st.conn) == 0, "close-timeout wioClose failed");
    require(st.conn->close == 1 && st.conn->closed == 0, "close-timeout path did not defer the graceful close");

    for (int i = 0; i < 500 && st.closes == 0; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.closes == 1, "close timeout did not force the deferred close");
    require(wioGetError(st.conn) == ETIMEDOUT, "close timeout did not preserve ETIMEDOUT");
    require(wioIsClosed(st.conn), "close timeout left the io open");
    require(st.conn->close_timer == NULL, "forced close left the close timer armed");

    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "close-timeout operations did not return to baseline");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 10: hard close deletes every armed per-io timer before callback/reuse.
// ---------------------------------------------------------------------------

typedef struct timer_close_state_s
{
    wio_t *conn;
    int    closes;
    int    heartbeats;
} timer_close_state_t;

static void timerClose(wio_t *io)
{
    timer_close_state_t *st = weventGetUserdata(io);
    st->closes++;
}

static void timerHeartbeat(wio_t *io)
{
    timer_close_state_t *st = weventGetUserdata(io);
    st->heartbeats++;
}

static void timerCloseAccept(wio_t *connio)
{
    timer_close_state_t *st = weventGetUserdata(connio);
    require(st->conn == NULL, "timer-close test accepted more than one connection");
    st->conn = connio;
    wioSetCallBackClose(connio, timerClose);
}

static void testCloseDeletesTimers(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "timer-close loop create failed");

    timer_close_state_t st     = {0};
    wio_t              *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, timerCloseAccept);
    require(server != NULL, "timer-close server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "timer-close connection was not accepted");

    wioSetReadTimeout(st.conn, 50);
    wiosSetWriteTimeout(st.conn, 60);
    wioSetKeepaliveTimeout(st.conn, 70);
    wioSetHeartBeat(st.conn, 80, timerHeartbeat);
    wioSetCloseTimeout(st.conn, 90);
    require(st.conn->read_timer != NULL, "read timeout did not arm a timer");
    require(st.conn->write_timer != NULL, "write timeout did not arm a timer");
    require(st.conn->keepalive_timer != NULL, "keepalive timeout did not arm a timer");
    require(st.conn->heartbeat_timer != NULL, "heartbeat interval did not arm a timer");

    // Accepted sockets currently do not set this flag, so make the close-callback
    // state transition explicit and cover the stale-connected IOCP regression.
    st.conn->connected = 1;
    require(wioClose(st.conn) == 0, "timer-close wioClose failed");
    require(st.closes == 1, "timer-close callback did not run exactly once");
    require(st.conn->connect_timer == NULL && st.conn->close_timer == NULL && st.conn->read_timer == NULL &&
                st.conn->write_timer == NULL && st.conn->keepalive_timer == NULL && st.conn->heartbeat_timer == NULL,
            "hard close left a per-io timer armed");
    require(st.conn->connected == 0, "hard close did not clear connected before its callback");

    wioFree(st.conn);
    for (int i = 0; i < 50; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.closes == 1, "a deleted timeout fired after the io was freed");
    require(st.heartbeats == 0, "a deleted heartbeat fired after the io was freed");

    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "timer-close operations did not return to baseline");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 11: wioFree overrides an earlier graceful-close deferral.
// ---------------------------------------------------------------------------

static void testFreeDuringDeferredClose(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "deferred-free loop create failed");

    close_drain_state_t st     = {0};
    wio_t              *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, closeDrainAccept);
    require(server != NULL, "deferred-free server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "deferred-free connection was not accepted");

    (void) forceQueuedSend(st.conn, env->buffer_pool, 'F', SEND_TEST_BACKPRESSURE_BYTES);
    require(wioClose(st.conn) == 0, "deferred-free graceful close failed");
    require(st.conn->close == 1 && st.conn->close_timer != NULL, "deferred-free close was not initially deferred");
    require(wioGetIocpLiveRecords(st.conn) > 0, "deferred-free test has no record keeping the io alive");

    int conn_fd = wioGetFD(st.conn);
    wioFree(st.conn);
    // The live IOCP record checked above defers pool reuse, so st.conn remains
    // valid until the cancellation completion is retired by the event loop.
    require(st.closes == 1, "wioFree did not force the deferred close immediately");
    require(st.conn->destroy == 1 && st.conn->closed == 1, "wioFree left the deferred io open");
    require(st.conn->close_timer == NULL, "wioFree left the deferred close timer armed");
    require(write_queue_empty(&st.conn->write_queue), "wioFree did not recycle the software write queue");
    require(wioGetWriteBufSize(st.conn) == 0, "wioFree did not reset queued send accounting");
    require(loop->ios.ptr[conn_fd] == NULL, "wioFree left the deferred io in the descriptor table");

    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "deferred-free operations did not return to baseline");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 12: a forced WSASend callback can free its wio synchronously.
// ---------------------------------------------------------------------------

typedef struct send_free_state_s
{
    wio_t *conn;
    int    write_callbacks;
    int    closed;
} send_free_state_t;

static void sendFreeClose(wio_t *io)
{
    send_free_state_t *st = weventGetUserdata(io);
    st->closed++;
}

static void sendThenFree(wio_t *io)
{
    send_free_state_t *st = weventGetUserdata(io);
    st->write_callbacks++;
    wioFree(io);
}

static void sendFreeAccept(wio_t *connio)
{
    send_free_state_t *st = weventGetUserdata(connio);
    require(st->conn == NULL, "send-free test accepted more than one connection");
    st->conn = connio;
    wioSetCallBackClose(connio, sendFreeClose);

    int send_buffer_size = 1024;
    require(setsockopt(
                wioGetFD(connio), SOL_SOCKET, SO_SNDBUF, (const char *) &send_buffer_size, sizeof(send_buffer_size)) ==
                0,
            "failed to reduce the send-free socket buffer");
}

static void testWriteCallbackFree(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    send_free_state_t st     = {0};
    wio_t            *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, sendFreeAccept);
    require(server != NULL, "send-free server create failed");
    weventSetUserData(server, &st);

    SOCKET client = connectClient(boundPort(server));
    for (int i = 0; i < 200 && st.conn == NULL; ++i)
    {
        wloopProcessEvents(loop, 10);
    }
    require(st.conn != NULL, "send-free connection was not accepted");

    for (int i = 0; i < 4096 && st.conn->iocp_send_active == NULL; ++i)
    {
        require(wioWrite(st.conn, makeFilledBuffer(env->buffer_pool, 'C', SEND_TEST_CHUNK_SIZE)) >= 0,
                "failed while forcing send-free WSASend");
    }
    require(st.conn->iocp_send_active != NULL, "send-free test did not force WSASend");
    wioSetCallBackWrite(st.conn, sendThenFree);
    setSocketNonblocking(client);

    char discard_buffer[16384];
    for (int attempt = 0; attempt < 20000 && st.closed == 0; ++attempt)
    {
        wloopProcessEvents(loop, 1);
        while (recv(client, discard_buffer, sizeof(discard_buffer), 0) > 0)
        {
        }
        int err = WSAGetLastError();
        require(err == WSAEWOULDBLOCK || st.closed != 0, "unexpected recv error in send-free test");
    }
    require(st.write_callbacks == 1, "send-free write callback did not run exactly once");
    require(st.closed == 1, "send callback wioFree did not close exactly once");

    wioClose(server);
    closesocket(client);
    require(pumpUntilLiveOperations(loop, 0, 500), "send-free test operations did not drain");
    wloopDestroy(&loop);
}

// ---------------------------------------------------------------------------
// Test 13: destroying a loop with AcceptEx records still posted drains cleanly.
// ---------------------------------------------------------------------------

static void neverAccept(wio_t *connio)
{
    (void) connio;
}

static void testDestroyWithPending(env_t *env)
{
    wloop_t *loop = wloopCreate(0, env->buffer_pool, 0);
    require(loop != NULL, "loop create failed");

    wio_t *server = wloopCreateTcpServer(loop, "127.0.0.1", 0, neverAccept);
    require(server != NULL, "tcp server create failed");
    require(wloopGetIocpPostedOperations(loop) >= 1, "listener posted no AcceptEx records");

    // No client connects: the AcceptEx records stay posted. wloopDestroy must
    // request cancellation and drain their completions before freeing memory
    // rather than closing the IOCP handle out from under them.
    wloopDestroy(&loop);
    // Reaching here without a hang or crash is the assertion; the drain has a
    // diagnostic deadline so a stuck operation cannot block forever.
}

int main(void)
{
    WSADATA wsa;
    require(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "WSAStartup failed");

    require(strcmp(wioGetEngine(), "iocp") == 0, "native IOCP backend not selected");

    env_t env;
    envSetup(&env);

    testEchoRoundTrip(&env);
    testCloseListenerFromAccept(&env);
    testReadCallbackCloses(&env);
    testReadStopAfterDequeue(&env);
    testPendingFreeAndDescriptorReuse(&env);
    testConnectCallbackFreeAndFamilies(&env);
    testSerializedSendQueue(&env);
    testCloseDrainsWriteQueue(&env);
    testCloseTimeoutForcesClose(&env);
    testCloseDeletesTimers(&env);
    testFreeDuringDeferredClose(&env);
    testWriteCallbackFree(&env);
    testDestroyWithPending(&env);

    envTeardown(&env);

    WSACleanup();
    printf("iocp_native_test: all checks passed\n");
    return 0;
}

#endif // EVENT_IOCP
