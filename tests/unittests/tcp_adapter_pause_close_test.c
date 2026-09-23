#ifdef TCP_PAUSE_TEST_LISTENER
#include "TcpListener/structure.h"
typedef tcplistener_lstate_t adapter_lstate_t;
typedef tcplistener_tstate_t adapter_tstate_t;
#else
#include "TcpConnector/structure.h"
typedef tcpconnector_lstate_t adapter_lstate_t;
typedef tcpconnector_tstate_t adapter_tstate_t;
#endif

#include "splice_buffer.h"
#include "tunnel_line_failure_harness.h"

#include <sys/socket.h>
#include <unistd.h>

static tunnel_t *adapter, *neighbor;
static line_t   *expected_line;
static bool      close_on_pause;
static uint32_t  pause_calls;
static bool      nested_payload;

static void submit(line_t *line, sbuf_t *buf)
{
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerTunnelDownStreamPayload(adapter, line, buf);
#else
    tcpconnectorTunnelUpStreamPayload(adapter, line, buf);
#endif
}

static void finishLine(line_t *line)
{
#ifdef TCP_PAUSE_TEST_LISTENER
    // TcpListener owns this normal line and must destroy it on downstream Finish.
    tcplistenerTunnelDownStreamFinish(adapter, line);
#else
    // TcpConnector borrows this normal line; the fake previous neighbor is its owner.
    tcpconnectorTunnelUpStreamFinish(adapter, line);
    twfRequire(lineIsAlive(line), "connector destroyed its borrowed line");
    lineDestroy(line);
#endif
}

static void onPause(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor && line == expected_line, "Pause used the wrong neighbor or line");
    ++pause_calls;
    adapter_lstate_t *ls = lineGetState(line, adapter);
    twfRequire(bufferqueueGetBufCount(&ls->pause_queue) == 2, "Pause preceded incoming FIFO admission");
    twfRequire(ls->queue_pause_sent, "Pause latch was not published before callback");
    if (nested_payload)
    {
        nested_payload = false;
        sbuf_t *buf    = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
        sbufWrite(buf, "nested", 6);
        sbufSetLength(buf, 6);
        submit(line, buf);
    }
    if (close_on_pause)
    {
        finishLine(line);
    }
}

static void unexpectedExpiry(local_idle_item_t *item)
{
    discard item;
    twfRequire(false, "pause fixture unexpectedly expired");
}

static sbuf_t *makeInput(buffer_pool_t *pool, bool splice_input)
{
    sbuf_t *buf;
    if (splice_input)
    {
#if WW_HAVE_SPLICE
        buf = bufferpoolGetSpliceBuffer(pool);
        twfRequire(buf != NULL, "failed to check out input private pipe");
        twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], "payload", 7) == 7, "failed to fill input private pipe");
        buf->capacity = (uint32_t) buf->l_pad + 7;
#else
        twfRequire(false, "splice fixture is unsupported");
        return NULL;
#endif
    }
    else
    {
        buf = bufferpoolGetLargeBuffer(pool);
        sbufWrite(buf, "payload", 7);
    }
    sbufSetLength(buf, 7);
    sbufShiftLeft(buf, 4);
    sbufWrite(buf, "HDR:", 4);
    return buf;
}

static void runPauseCase(bool splice_input, bool close_line)
{
    twfSetCase(
        close_line
            ? (splice_input ? "Pause closes line with splice input" : "Pause closes line with ordinary input")
            : (splice_input ? "Pause preserves line with splice input" : "Pause preserves line with ordinary input"));
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 64);
    adapter  = tunnelCreate(NULL, sizeof(adapter_tstate_t), sizeof(adapter_lstate_t));
    neighbor = tunnelCreate(NULL, 0, 0);
    twfRequire(adapter != NULL && neighbor != NULL, "failed to create pause fixture tunnels");
#ifdef TCP_PAUSE_TEST_LISTENER
    tunnelBind(adapter, neighbor);
    neighbor->fnPauseU = onPause;
#else
    tunnelBind(neighbor, adapter);
    neighbor->fnPauseD = onPause;
#endif
    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, adapter->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);
    // Observe logical death and zeroed state without relying on freed storage.
    lineRef(line);
    int sockets[2];
    twfRequire(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create adapter socket pair");
    wio_t *io = wioGet(env.loop, sockets[0]);
    twfRequire(io != NULL && ! wioIsClosed(io), "failed to adopt adapter socket");
    adapter_lstate_t *ls = lineGetState(line, adapter);
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerLinestateInitialize(ls, io, adapter, line);
#else
    tcpconnectorLinestateInitialize(ls);
    ls->tunnel      = adapter;
    ls->line        = line;
    ls->io          = io;
    ls->buffer_pool = env.pool;
#endif
    adapter_tstate_t   *ts    = tunnelGetState(adapter);
    local_idle_table_t *table = localIdleTableCreate(env.loop);
    twfRequire(table != NULL, "failed to create adapter idle table");
    local_idle_table_t *tables[1] = {table};
    ts->idle_tables               = tables;
    ls->idle_handle               = localidletableCreateItem(table, wioGetID(io), ls, unexpectedExpiry, 60000);
    twfRequire(ls->idle_handle != NULL, "failed to register adapter idle item");
    ls->write_paused = true;
    weventSetUserData(io, ls);

    sbuf_t *queued = bufferpoolGetLargeBuffer(env.pool);
    sbufSetLength(queued, kMinPauseQueueSize + 1);
    memorySet(sbufGetMutablePtr(queued), 'Q', sbufGetLength(queued));
    queued                         = bufferqueuePushBack(&ls->pause_queue, queued);
    sbuf_t        *input           = makeInput(env.pool, splice_input);
    const uint32_t recycled_before = twfRecycleCount();
    close_on_pause                 = close_line;
    nested_payload                 = ! close_line;
    expected_line                  = line;
    pause_calls                    = 0;
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerTunnelDownStreamPayload(adapter, line, input);
#else
    tcpconnectorTunnelUpStreamPayload(adapter, line, input);
#endif
    expected_line = NULL;
    twfRequireEqualU32(pause_calls, 1, "adapter did not emit exactly one Pause");
    if (close_line)
    {
        twfRequire(! lineIsAlive(line) && wioIsClosed(io), "reentrant Finish did not close the line and socket");
        twfRequireLineStateZeroed(line, adapter, "paused write reused destroyed line state");
        twfRequireEqualU32(
            twfRecycleCount(), recycled_before + 2, "queued and still-local buffers were not settled once");

        if (splice_input)
        {
            sbuf_t *reused = bufferpoolGetSpliceBuffer(env.pool);
            twfRequire(reused == input && sbufSpliceIsReusable(reused), "unconsumed private body was not discarded");
            bufferpoolReuseBuffer(env.pool, reused);
        }
    }
    else
    {
        twfRequire(lineIsAlive(line) && twfLineRefCount(line) == 2, "surviving Pause leaked a line reference");
        twfRequire(bufferqueueGetBufCount(&ls->pause_queue) == 3 &&
                       bufferqueueGetBufLen(&ls->pause_queue) == kMinPauseQueueSize + 18,
                   "surviving Pause lost queue entries or bytes");
        sbuf_t *first = bufferqueuePopFront(&ls->pause_queue);
        twfRequire(sbufGetLength(first) == kMinPauseQueueSize + 1 && memoryEqual(sbufGetRawPtr(first), "Q", 1),
                   "surviving Pause changed FIFO order");
        bufferpoolReuseBuffer(env.pool, first);
        sbuf_t *received = bufferqueuePopFront(&ls->pause_queue);
        if (splice_input)
        {
            twfRequire(received == input, "surviving Pause replaced a splice wrapper");
            received = sbufSpliceMaterializeToBuffer(received, bufferpoolGetLargeBuffer(env.pool), env.pool);
        }
        twfRequire(sbufGetLength(received) == 11 && memoryEqual(sbufGetRawPtr(received), "HDR:payload", 11),
                   "surviving Pause corrupted its input payload");
        bufferpoolReuseBuffer(env.pool, received);
        sbuf_t *nested = bufferqueuePopFront(&ls->pause_queue);
        twfRequire(sbufGetLength(nested) == 6 && memoryEqual(sbufGetRawPtr(nested), "nested", 6),
                   "nested payload overtook older input");
        bufferpoolReuseBuffer(env.pool, nested);
        finishLine(line);
        twfRequireLineStateZeroed(line, adapter, "normal cleanup left adapter state alive");
    }
    twfRequireEqualU32(twfLineRefCount(line), 1, "closed line retained unexpected references");
    lineUnref(line);
    twfRequire(masterpoolGetCheckedOut(line_pool.master) == 0, "line was not returned to its pool");
    twfRequireNoLeakedBuffers();
    localidletableDestroy(table);
    close(sockets[1]);
    twfLinePoolTeardown(&line_pool);
    tunnelDestroy(adapter);
    tunnelDestroy(neighbor);
    twfWorkerEnvTeardown(&env);
}

static void onOverflow(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor, "overflow notified wrong neighbor");
#ifndef TCP_PAUSE_TEST_LISTENER
    lineDestroy(line);
#else
    discard line;
#endif
}

static void onCapacityPause(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor && lineIsAlive(line), "invalid capacity Pause");
    ++pause_calls;
}

static void runCapacityCase(void)
{
    twfSetCase("TCP empty queued buffers hit finite capacity budget");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 64);
    adapter  = tunnelCreate(NULL, sizeof(adapter_tstate_t), sizeof(adapter_lstate_t));
    neighbor = tunnelCreate(NULL, 0, 0);
    twfRequire(adapter != NULL && neighbor != NULL, "failed to create pause fixture tunnels");
#ifdef TCP_PAUSE_TEST_LISTENER
    tunnelBind(adapter, neighbor);
    neighbor->fnPauseU = onPause;
#else
    tunnelBind(neighbor, adapter);
    neighbor->fnPauseD = onPause;
#endif
    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, adapter->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);
    // Observe logical death and zeroed state without relying on freed storage.
    lineRef(line);
    int sockets[2];
    twfRequire(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create adapter socket pair");
    wio_t *io = wioGet(env.loop, sockets[0]);
    twfRequire(io != NULL && ! wioIsClosed(io), "failed to adopt adapter socket");
    adapter_lstate_t *ls = lineGetState(line, adapter);
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerLinestateInitialize(ls, io, adapter, line);
#else
    tcpconnectorLinestateInitialize(ls);
    ls->tunnel      = adapter;
    ls->line        = line;
    ls->io          = io;
    ls->buffer_pool = env.pool;
#endif
    adapter_tstate_t   *ts    = tunnelGetState(adapter);
    local_idle_table_t *table = localIdleTableCreate(env.loop);
    twfRequire(table != NULL, "failed to create adapter idle table");
    local_idle_table_t *tables[1] = {table};
    ts->idle_tables               = tables;
    ls->idle_handle               = localidletableCreateItem(table, wioGetID(io), ls, unexpectedExpiry, 60000);
    twfRequire(ls->idle_handle != NULL, "failed to register adapter idle item");
    ls->write_paused = true;
    weventSetUserData(io, ls);

#ifdef TCP_PAUSE_TEST_LISTENER
    neighbor->fnFinU   = onOverflow;
    neighbor->fnPauseU = onCapacityPause;
#else
    neighbor->fnFinD   = onOverflow;
    neighbor->fnPauseD = onCapacityPause;
#endif
    pause_calls              = 0;
    size_t   accepted_charge = 0;
    unsigned entries         = 0;
    while (lineIsAlive(line))
    {
        // Large capacity, zero logical length: byte-only admission never refuses this.
        sbuf_t      *buf    = sbufCreate(1024 * 1024);
        const size_t charge = sbufGetQueueCharge(buf);
        const bool   fits   = accepted_charge <= kMaxPauseQueueSize - charge;
        submit(line, buf);
        ++entries;
        if (fits)
        {
            accepted_charge += charge;
            twfRequire(lineIsAlive(line), "capacity refused before hard ceiling");
            twfRequire(bufferqueueGetCharge(&ls->pause_queue) == accepted_charge, "incremental charge mismatch");
            twfRequire(bufferqueueGetBufLen(&ls->pause_queue) == 0, "empty buffers acquired logical bytes");
        }
        else
            twfRequire(! lineIsAlive(line), "capacity overflow did not settle line");
        twfRequire(entries <= 16, "zero-byte queue is not bounded");
    }
    twfRequireEqualU32(pause_calls, 1, "capacity pressure did not latch Pause");
    twfRequireLineStateZeroed(line, adapter, "overflow left state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "closed line retained unexpected references");
    lineUnref(line);
    twfRequire(masterpoolGetCheckedOut(line_pool.master) == 0, "line was not returned to its pool");
    twfRequireNoLeakedBuffers();
    localidletableDestroy(table);
    close(sockets[1]);
    twfLinePoolTeardown(&line_pool);
    tunnelDestroy(adapter);
    tunnelDestroy(neighbor);
    twfWorkerEnvTeardown(&env);
}

static void onDrainResume(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor, "drain resumed wrong neighbor");
    adapter_lstate_t *ls = lineGetState(line, adapter);
    twfRequire(! ls->write_paused && ! ls->queue_pause_sent && ls->active_write.cost.charge == 0 &&
                   bufferqueueGetCharge(&ls->pause_queue) == 0,
               "Resume preceded drain/accounting settlement");
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 1);
    sbufWrite(buf, "C", 1);
    submit(line, buf);
    finishLine(line);
}

static void runWriteCompletionCase(void)
{
    twfSetCase("TCP write completion preserves FIFO across nested Resume and Finish");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 64);
    adapter  = tunnelCreate(NULL, sizeof(adapter_tstate_t), sizeof(adapter_lstate_t));
    neighbor = tunnelCreate(NULL, 0, 0);
    twfRequire(adapter != NULL && neighbor != NULL, "failed to create pause fixture tunnels");
#ifdef TCP_PAUSE_TEST_LISTENER
    tunnelBind(adapter, neighbor);
    neighbor->fnPauseU = onPause;
#else
    tunnelBind(neighbor, adapter);
    neighbor->fnPauseD = onPause;
#endif
    twf_line_pool_t line_pool;
    twfLinePoolSetup(&line_pool, adapter->lstate_size, 1);
    line_t *line = twfLinePoolCreateLine(&line_pool);
    // Observe logical death and zeroed state without relying on freed storage.
    lineRef(line);
    int sockets[2];
    twfRequire(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "failed to create adapter socket pair");
    wio_t *io = wioGet(env.loop, sockets[0]);
    twfRequire(io != NULL && ! wioIsClosed(io), "failed to adopt adapter socket");
    adapter_lstate_t *ls = lineGetState(line, adapter);
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerLinestateInitialize(ls, io, adapter, line);
#else
    tcpconnectorLinestateInitialize(ls);
    ls->tunnel      = adapter;
    ls->line        = line;
    ls->io          = io;
    ls->buffer_pool = env.pool;
#endif
    adapter_tstate_t   *ts    = tunnelGetState(adapter);
    local_idle_table_t *table = localIdleTableCreate(env.loop);
    twfRequire(table != NULL, "failed to create adapter idle table");
    local_idle_table_t *tables[1] = {table};
    ts->idle_tables               = tables;
    ls->idle_handle               = localidletableCreateItem(table, wioGetID(io), ls, unexpectedExpiry, 60000);
    twfRequire(ls->idle_handle != NULL, "failed to register adapter idle item");
    ls->write_paused = true;
    weventSetUserData(io, ls);

#ifdef TCP_PAUSE_TEST_LISTENER
    neighbor->fnPauseU  = onCapacityPause;
    neighbor->fnResumeU = onDrainResume;
#else
    neighbor->fnPauseD  = onCapacityPause;
    neighbor->fnResumeD = onDrainResume;
#endif
    for (unsigned i = 0; i < 2; ++i)
    {
        sbuf_t *buf = bufferpoolGetLargeBuffer(env.pool);
        sbufSetLength(buf, 1);
        sbufWrite(buf, i == 0 ? "A" : "B", 1);
        submit(line, buf);
    }
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerOnWriteComplete(io);
#else
    tcpconnectorOnWriteComplete(io);
#endif
    twfRequire(! lineIsAlive(line), "nested Resume Finish left line alive");
    char wire[3];
    twfRequire(recv(sockets[1], wire, sizeof(wire), MSG_WAITALL) == sizeof(wire) && memoryEqual(wire, "ABC", 3),
               "write completion reentry changed FIFO bytes");
    twfRequireLineStateZeroed(line, adapter, "nested drain close left state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "closed line retained unexpected references");
    lineUnref(line);
    twfRequire(masterpoolGetCheckedOut(line_pool.master) == 0, "line was not returned to its pool");
    twfRequireNoLeakedBuffers();
    localidletableDestroy(table);
    close(sockets[1]);
    twfLinePoolTeardown(&line_pool);
    tunnelDestroy(adapter);
    tunnelDestroy(neighbor);
    twfWorkerEnvTeardown(&env);
}

typedef struct tcp_progress_fixture_s
{
    twf_worker_env_t    env;
    tunnel_chain_t     *chain;
    local_idle_table_t *tables[1];
    line_t             *line;
    wio_t              *io;
    int                 peer;
    unsigned            resumes, finishes;
    unsigned            init_calls, est_calls;
    tunnel_t           *resolver;
    node_t              resolver_node;
} tcp_progress_fixture_t;
static tcp_progress_fixture_t *progress_fixture;

static void progressInit(tunnel_t *t, line_t *line)
{
    discard t;
    progress_fixture->line = line;
    ++progress_fixture->init_calls;
}
static void progressFinish(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor, "write failure finished the wrong neighbor");
    ++progress_fixture->finishes;
    twfRequireLineStateZeroed(line, adapter, "terminal callback preceded adapter cleanup");
#ifndef TCP_PAUSE_TEST_LISTENER
    lineDestroy(line);
#endif
}
static void progressResume(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor && lineIsAlive(line), "write progress resumed a dead/wrong line");
    adapter_lstate_t *ls = lineGetState(line, adapter);
    twfRequire(! ls->write_paused && ! ls->queue_pause_sent && ls->active_write.cost.charge == 0 &&
                   bufferqueueGetCharge(&ls->pause_queue) == 0,
               "write progress resumed before all retained allocation charges were released");
    ++progress_fixture->resumes;
}
static void progressSetup(tcp_progress_fixture_t *fixture, bool with_resolver)
{
    memoryZero(fixture, sizeof(*fixture));
    progress_fixture = fixture;
    twfWorkerEnvSetup(&fixture->env, 4096, 64);
    fixture->env.loop->status = WLOOP_STATUS_RUNNING;
    adapter                   = tunnelCreate(NULL, sizeof(adapter_tstate_t), sizeof(adapter_lstate_t));
    neighbor                  = tunnelCreate(NULL, 0, 0);
    twfRequire(adapter != NULL && neighbor != NULL, "failed to construct write-progress tunnels");
    adapter_tstate_t *ts                = tunnelGetState(adapter);
    ts->idle_tables                     = fixture->tables;
    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = adapter->lstate_size;
#ifndef TCP_PAUSE_TEST_LISTENER
    if (with_resolver)
    {
        fixture->resolver_node = nodeDomainResolverGet();
        fixture->resolver      = fixture->resolver_node.createHandle(&fixture->resolver_node);
        twfRequire(fixture->resolver != NULL, "failed to construct real resolver prefix");
        adapter->lstate_offset = fixture->resolver->lstate_size;
        fixture->chain->sum_line_state_size += fixture->resolver->lstate_size;
    }
#else
    discard with_resolver;
#endif
    tunnelchainFinalize(fixture->chain);
    adapter->chain = fixture->chain;
    int sockets[2];
    twfRequire(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0, "progress socketpair failed");
    int send_size = 4096;
    twfRequire(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &send_size, sizeof(send_size)) == 0,
               "failed to limit fixture socket send buffer");
    fixture->peer = sockets[1];
    fixture->io   = wioGet(fixture->env.loop, sockets[0]);
    twfRequire(fixture->io != NULL && ! wioIsClosed(fixture->io), "progress WIO adoption failed");
#ifdef TCP_PAUSE_TEST_LISTENER
    tunnelBind(adapter, neighbor);
    neighbor->fnInitU           = progressInit;
    neighbor->fnPauseU          = onCapacityPause;
    neighbor->fnResumeU         = progressResume;
    neighbor->fnFinU            = progressFinish;
    ts->initial_idle_timeout_ms = ts->active_idle_timeout_ms = 60000;
    struct sockaddr_in peer                                  = {
                                         .sin_family = AF_INET, .sin_port = htons(1234), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    wioSetPeerAddr(fixture->io, (struct sockaddr *) &peer, sizeof(peer));
    wioDetach(fixture->io);
    socket_accept_result_t *accepted = memoryAllocateZero(sizeof(*accepted));
    accepted->io                     = fixture->io;
    accepted->tunnel                 = adapter;
    accepted->wid                    = 0;
    accepted->real_localport         = 1234;
    wevent_t event                   = {.loop = fixture->env.loop};
    weventSetUserData(&event, accepted);
    tcplistenerOnInboundConnected(&event);
    twfRequire(fixture->line != NULL, "listener did not admit fixture line");
    // The test drives only writes; peer closure must be observed by the write path.
    wioReadStop(fixture->io);
#else
    tunnelBind(neighbor, adapter);
    if (fixture->resolver != NULL)
    {
        tunnelBind(neighbor, fixture->resolver);
        tunnelBind(fixture->resolver, adapter);
        fixture->resolver->chain = fixture->chain;
        adapter->fnInitU         = progressInit;
        adapter->fnFinU          = tcpconnectorTunnelUpStreamFinish;
        adapter->fnPayloadU      = tcpconnectorTunnelUpStreamPayload;
        adapter->fnPauseU        = tcpconnectorTunnelUpStreamPause;
        adapter->fnResumeU       = tcpconnectorTunnelUpStreamResume;
    }
    neighbor->fnPauseD        = onCapacityPause;
    neighbor->fnResumeD       = progressResume;
    neighbor->fnFinD          = progressFinish;
    fixture->line             = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    tcpconnector_lstate_t *ls = lineGetState(fixture->line, adapter);
    tcpconnectorLinestateInitialize(ls);
    ls->tunnel         = adapter;
    ls->line           = fixture->line;
    ls->io             = fixture->io;
    ls->buffer_pool    = fixture->env.pool;
    fixture->tables[0] = localIdleTableCreate(fixture->env.loop);
    ls->idle_handle = localidletableCreateItem(fixture->tables[0], wioGetID(fixture->io), ls, unexpectedExpiry, 60000);
    twfRequire(ls->idle_handle != NULL, "failed to register write-progress idle item");
    weventSetUserData(fixture->io, ls);
    wioSetCallBackClose(fixture->io, tcpconnectorOnClose);
#endif
    lineRef(fixture->line);
    pause_calls = 0;
}
static void progressTeardown(tcp_progress_fixture_t *fixture)
{
    if (lineIsAlive(fixture->line))
    {
        if (fixture->resolver != NULL)
        {
            fixture->resolver->fnFinU(fixture->resolver, fixture->line);
            twfRequireLineStateZeroed(fixture->line, fixture->resolver, "resolver state survived source Finish");
            lineDestroy(fixture->line);
        }
        else
            finishLine(fixture->line);
    }
    twfRequireLineStateZeroed(fixture->line, adapter, "write-progress state survived close");
    twfRequire(twfLineRefCount(fixture->line) == 1, "write-progress line reference leaked");
    lineUnref(fixture->line);
    twfRequireNoLeakedBuffers();
    localidletableDestroy(fixture->tables[0]);
    if (fixture->peer >= 0)
        close(fixture->peer);
    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(adapter);
    if (fixture->resolver != NULL)
    {
        fixture->resolver->onDestroy(fixture->resolver, wwLifecycleStartupRollback());
        memoryFree(fixture->resolver_node.type);
    }
    tunnelDestroy(neighbor);
    twfWorkerEnvTeardown(&fixture->env);
}
static size_t progressReadPeer(tcp_progress_fixture_t *fixture, size_t offset, size_t body_bytes)
{
    char chunk[16384];
    for (;;)
    {
        ssize_t n = recv(fixture->peer, chunk, sizeof(chunk), MSG_DONTWAIT);
        if (n <= 0)
        {
            twfRequire(n == 0 || errno == EAGAIN || errno == EWOULDBLOCK, "unexpected progress peer read failure");
            return offset;
        }
        for (ssize_t i = 0; i < n; ++i, ++offset)
        {
            char expected = offset < body_bytes ? 'A' : offset == body_bytes ? 'B' : 'C';
            twfRequire(offset < body_bytes + 2 && chunk[i] == expected, "partial-write drain changed FIFO bytes");
        }
    }
}
static void runActiveWriteChargeCase(bool overflow)
{
    twfSetCase(overflow ? "partial active WIO allocation plus adapter queue obeys exact combined hard limit"
                        : "partial WIO progress retains allocation charge and drains queued suffix in FIFO order");
    tcp_progress_fixture_t fixture;
    progressSetup(&fixture, false);
    adapter_lstate_t *ls         = lineGetState(fixture.line, adapter);
    const uint32_t    body_bytes = 256 * 1024;
    sbuf_t           *active     = twfTrackAcquired(sbufCreate(kMaxPauseQueueSize / 2));
    sbufSetLength(active, body_bytes);
    memorySet(sbufGetMutablePtr(active), 'A', body_bytes);
    const size_t active_charge = sbufGetQueueCharge(active);
    submit(fixture.line, active);
    size_t pending_bytes = wioGetWriteBufSize(fixture.io);
    twfRequire(pending_bytes > 0 && pending_bytes < body_bytes && ls->write_paused &&
                   ls->active_write.cost.charge == active_charge && bufferqueueGetCharge(&ls->pause_queue) == 0 &&
                   pause_calls == 1,
               "real socket write did not retain the partial active allocation");
    twfRequire(ls->active_write.budget == &ls->write_budget &&
                   bufferbudgetGetUsage(&ls->write_budget).bytes == pending_bytes &&
                   bufferbudgetGetUsage(&ls->write_budget).entries == 1,
               "direct WIO return did not reconcile active logical bytes");
    const size_t suffix_capacity = kMaxPauseQueueSize - active_charge - sizeof(sbuf_t) - kSbufAllocationAlignment;
    sbuf_t      *suffix          = twfTrackAcquired(sbufCreate((uint32_t) suffix_capacity));
    sbufWrite(suffix, "BC", 2);
    sbufSetLength(suffix, 2);
    submit(fixture.line, suffix);
    twfRequire(lineIsAlive(fixture.line) &&
                   ls->active_write.cost.charge + bufferqueueGetCharge(&ls->pause_queue) == kMaxPauseQueueSize,
               "exact combined active-plus-queue charge was refused or uncharged");
    size_t  received = progressReadPeer(&fixture, 0, body_bytes);
    discard wloopProcessEvents(fixture.env.loop, 0);
    twfRequire(wioGetWriteBufSize(fixture.io) < pending_bytes && wioGetWriteBufSize(fixture.io) > 0 &&
                   ls->active_write.cost.charge == active_charge &&
                   ls->active_write.cost.charge + bufferqueueGetCharge(&ls->pause_queue) == kMaxPauseQueueSize,
               "partial WIO progress released allocation charge before completion");
    twfRequire(ls->active_write.cost.bytes == wioGetWriteBufSize(fixture.io) &&
                   bufferbudgetGetUsage(&ls->write_budget).bytes == wioGetWriteBufSize(fixture.io) + 2 &&
                   bufferbudgetGetUsage(&ls->write_budget).entries == 2,
               "partial callback did not release only consumed logical bytes");
    if (overflow)
    {
        submit(fixture.line, twfTrackAcquired(sbufCreate(0)));
        twfRequire(! lineIsAlive(fixture.line) && fixture.finishes == 1 && fixture.resumes == 0,
                   "one-over active-plus-queue charge did not terminate the exact line");
    }
    for (unsigned i = 0; i < 1024 && ! wioCheckWriteComplete(fixture.io); ++i)
    {
        received = progressReadPeer(&fixture, received, body_bytes);
        discard wloopProcessEvents(fixture.env.loop, 0);
    }
    received = progressReadPeer(&fixture, received, body_bytes);
    twfRequire(wioCheckWriteComplete(fixture.io) && received == body_bytes + (overflow ? 0 : 2),
               "bounded partial-write fixture did not complete all surviving bytes");
    twfRequire(fixture.resumes == (overflow ? 0U : 1U), "partial-write drain repeated or omitted Resume");
    if (! overflow)
        twfRequire(ls->active_write.budget == NULL && bufferbudgetGetUsage(&ls->write_budget).entries == 0 &&
                       bufferqueueGetCharge(&ls->pause_queue) == 0,
                   "completed write leaked capacity charge");
    progressTeardown(&fixture);
}
static void runQueuedWriteFailureCase(void)
{
    twfSetCase("failed WIO write during adapter FIFO drain closes once without Resume or queued-suffix reuse");
    tcp_progress_fixture_t fixture;
    progressSetup(&fixture, false);
    adapter_lstate_t *ls = lineGetState(fixture.line, adapter);
    ls->write_paused     = true;
    for (unsigned i = 0; i < 2; ++i)
    {
        sbuf_t *buf = bufferpoolGetLargeBuffer(fixture.env.pool);
        sbufSetLength(buf, 1);
        sbufWrite(buf, i == 0 ? "A" : "B", 1);
        submit(fixture.line, buf);
    }
    close(fixture.peer);
    fixture.peer = -1;
#ifdef TCP_PAUSE_TEST_LISTENER
    tcplistenerOnWriteComplete(fixture.io);
#else
    tcpconnectorOnWriteComplete(fixture.io);
#endif
    twfRequire(fixture.resumes == 0, "failed FIFO write incorrectly resumed its producer");
    if (lineIsAlive(fixture.line))
        twfRequire(bufferqueueGetBufCount(&ls->pause_queue) == 1, "failed write continued into queued suffix");
    for (unsigned i = 0; i < 8 && lineIsAlive(fixture.line); ++i)
        discard wloopProcessEvents(fixture.env.loop, 0);
    twfRequire(! lineIsAlive(fixture.line) && fixture.finishes == 1 && fixture.resumes == 0,
               "asynchronous write failure did not settle the owner once");
    progressTeardown(&fixture);
}

#ifndef TCP_PAUSE_TEST_LISTENER
static LineDnsResolveFn connector_dns_callback;
static line_t          *connector_dns_line;
static tunnel_t        *connector_dns_tunnel;
static void            *connector_dns_userdata;

int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata);
int __wrap_lineResolveDomainServiceAsync(line_t *line, const char *domain, const char *service, int socktype,
                                         LineDnsResolveFn callback, tunnel_t *t, void *userdata)
{
    twfRequire(strcmp(domain, "connector.invalid") == 0 && service == NULL && socktype == SOCK_STREAM,
               "resolver fixture requested an unexpected DNS query");
    twfRequire(connector_dns_callback == NULL, "resolver repeated DNS before completion");
    connector_dns_callback = callback;
    connector_dns_line     = line;
    connector_dns_tunnel   = t;
    connector_dns_userdata = userdata;
    lineRef(line);
    return ARES_SUCCESS;
}
static void connectorEst(tunnel_t *t, line_t *line)
{
    twfRequire(t == neighbor && line == progress_fixture->line, "connector Est used the wrong association");
    ++progress_fixture->est_calls;
}
static void runResolverPreEstCase(bool literal)
{
    twfSetCase(literal ? "literal resolver path admits real connector payload before transport Est"
                       : "DNS completion transfers older payload into real connector before transport Est");
    tcp_progress_fixture_t fixture;
    progressSetup(&fixture, true);
    adapter_lstate_t *ls    = lineGetState(fixture.line, adapter);
    ls->write_paused        = true; // Mock only the pending socket connect; writes and completion use production paths.
    neighbor->fnEstD        = connectorEst;
    address_context_t *dest = lineGetDestinationAddressContext(fixture.line);
    if (literal)
        addresscontextSetIpAddress(dest, "127.0.0.1");
    else
        addresscontextDomainSet(dest, "connector.invalid", 17);
    addresscontextSetPort(dest, 443);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    connector_dns_callback = NULL;
    fixture.resolver->fnInitU(fixture.resolver, fixture.line);
    sbuf_t *first = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufWrite(first, "A", 1);
    sbufSetLength(first, 1);
    fixture.resolver->fnPayloadU(fixture.resolver, fixture.line, first);
    if (! literal)
    {
        twfRequire(fixture.init_calls == 0 && fixture.est_calls == 0 && connector_dns_callback != NULL &&
                       bufferqueueGetBufCount(&ls->pause_queue) == 0,
                   "DNS-pending payload reached a connector before adjacent Init");
        dns_resolved_addr_t answer = {.family = AF_INET, .addrlen = sizeof(struct sockaddr_in)};
        struct sockaddr_in *addr   = (struct sockaddr_in *) &answer.addr;
        addr->sin_family           = AF_INET;
        addr->sin_addr.s_addr      = htonl(INADDR_LOOPBACK);
        connector_dns_callback(
            connector_dns_tunnel, connector_dns_line, connector_dns_userdata, ARES_SUCCESS, NULL, &answer, 1);
        lineUnref(connector_dns_line);
        connector_dns_callback = NULL;
    }
    twfRequire(fixture.init_calls == 1 && fixture.est_calls == 0 && ls->write_paused &&
                   bufferqueueGetBufCount(&ls->pause_queue) == 1 && bufferqueueGetCharge(&ls->pause_queue) > 0 &&
                   pause_calls == 1,
               "initialized connector did not admit DNS/literal payload before Est");
    sbuf_t *second = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufWrite(second, "B", 1);
    sbufSetLength(second, 1);
    fixture.resolver->fnPayloadU(fixture.resolver, fixture.line, second);
    twfRequire(bufferqueueGetBufCount(&ls->pause_queue) == 2, "admitted connecting payload was lost after Pause");
    tcpconnectorOnOutBoundConnected(fixture.io);
    char received[2];
    twfRequire(recv(fixture.peer, received, sizeof(received), 0) == sizeof(received) &&
                   memoryEqual(received, "AB", 2) && fixture.est_calls == 1 && fixture.resumes == 1,
               "connect completion lost FIFO, Est or pressure release through resolver");
    twfRequire(! ls->write_paused && bufferqueueGetCharge(&ls->pause_queue) == 0 && ls->active_write.cost.charge == 0,
               "connector completion left pending accounting");
    progressTeardown(&fixture);
}
#endif

#ifdef TCP_PAUSE_TEST_LISTENER
void __wrap_socketacceptresultDestroy(socket_accept_result_t *result);
void __wrap_socketacceptresultDestroy(socket_accept_result_t *result)
{
    memoryFree(result);
}

static void pauseDuringInit(tunnel_t *t, line_t *line)
{
    discard t;
    expected_line = line;
    tcplistenerTunnelDownStreamPause(adapter, line);
}

static void runAcceptedInitPauseCase(void)
{
    twfSetCase("TcpListener preserves Pause received during accepted-line Init");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 4096, 64);
    adapter  = tunnelCreate(NULL, sizeof(adapter_tstate_t), sizeof(adapter_lstate_t));
    neighbor = tunnelCreate(NULL, 0, 0);
    twfRequire(adapter != NULL && neighbor != NULL, "failed to create accept fixture");
    tunnelBind(adapter, neighbor);
    neighbor->fnInitU             = pauseDuringInit;
    adapter_tstate_t   *ts        = tunnelGetState(adapter);
    local_idle_table_t *tables[1] = {NULL};
    ts->idle_tables               = tables;
    ts->initial_idle_timeout_ms   = 60000;
    tunnel_chain_t *chain         = tunnelchainCreate(1);
    chain->sum_line_state_size    = adapter->lstate_size;
    tunnelchainFinalize(chain);
    adapter->chain = chain;
    int sockets[2];
    twfRequire(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "accept socketpair failed");
    wio_t             *io   = wioGet(env.loop, sockets[0]);
    struct sockaddr_in peer = {
        .sin_family = AF_INET, .sin_port = htons(1234), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    wioSetPeerAddr(io, (struct sockaddr *) &peer, sizeof(peer));
    wioDetach(io);
    socket_accept_result_t *result = memoryAllocateZero(sizeof(*result));
    result->io                     = io;
    result->tunnel                 = adapter;
    result->wid                    = 0;
    result->real_localport         = 1234;
    wevent_t event                 = {.loop = env.loop};
    weventSetUserData(&event, result);
    expected_line = NULL;
    tcplistenerOnInboundConnected(&event);
    twfRequire(expected_line != NULL, "accepted line did not receive Init");
    adapter_lstate_t *ls = lineGetState(expected_line, adapter);
    twfRequire(ls->read_paused && ! (io->events & WW_READ), "accept restarted reads after Init Pause");
    tcplistenerTunnelDownStreamResume(adapter, expected_line);
    twfRequire(! ls->read_paused && (io->events & WW_READ), "genuine Resume did not enable reads");
    finishLine(expected_line);
    expected_line = NULL;
    localidletableDestroy(tables[0]);
    close(sockets[1]);
    tunnelchainDestroy(chain);
    tunnelDestroy(adapter);
    tunnelDestroy(neighbor);
    twfWorkerEnvTeardown(&env);
}
#endif

int main(void)
{
    runCapacityCase();
    runWriteCompletionCase();
    runActiveWriteChargeCase(false);
    runActiveWriteChargeCase(true);
    runQueuedWriteFailureCase();
#ifndef TCP_PAUSE_TEST_LISTENER
    runResolverPreEstCase(false);
    runResolverPreEstCase(true);
#endif
#ifdef TCP_PAUSE_TEST_LISTENER
    runAcceptedInitPauseCase();
#endif
#if WW_HAVE_SPLICE
    runPauseCase(true, true);
    runPauseCase(true, false);
#endif
    runPauseCase(false, true);
    runPauseCase(false, false);
    return 0;
}
