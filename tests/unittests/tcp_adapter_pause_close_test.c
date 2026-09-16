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
        buf = twfTrackAcquired(bufferpoolGetSpliceBuffer(pool));
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
    bufferqueuePushBack(&ls->pause_queue, queued);
    sbuf_t        *input           = makeInput(env.pool, splice_input);
    const uint32_t recycled_before = twfRecycleCount();
    close_on_pause                 = close_line;
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
        twfRequireLastRecycle(input, env.pool, "still-local input used the wrong pool after line destruction");
        if (splice_input)
        {
            sbuf_t *reused = twfTrackAcquired(bufferpoolGetSpliceBuffer(env.pool));
            twfRequire(reused == input && sbufSpliceIsReusable(reused), "unconsumed private body was not discarded");
            bufferpoolReuseBuffer(env.pool, reused);
        }
    }
    else
    {
        twfRequire(lineIsAlive(line) && twfLineRefCount(line) == 2, "surviving Pause leaked a line reference");
        twfRequire(bufferqueueGetBufCount(&ls->pause_queue) == 2 &&
                       bufferqueueGetBufLen(&ls->pause_queue) == kMinPauseQueueSize + 12,
                   "surviving Pause lost queue entries or bytes");
        sbuf_t *first = bufferqueuePopFront(&ls->pause_queue);
        twfRequire(sbufGetLength(first) == kMinPauseQueueSize + 1 && memoryEqual(sbufGetRawPtr(first), "Q", 1),
                   "surviving Pause changed FIFO order");
        bufferpoolReuseBuffer(env.pool, first);
        sbuf_t *received = bufferqueuePopFront(&ls->pause_queue);
        if (splice_input)
        {
            twfRequire(received == input, "surviving Pause replaced a splice wrapper");
            received = wioTransformSpliceBufferToRealBuffer(received, bufferpoolGetLargeBuffer(env.pool), env.pool);
        }
        twfRequire(sbufGetLength(received) == 11 && memoryEqual(sbufGetRawPtr(received), "HDR:payload", 11),
                   "surviving Pause corrupted its input payload");
        bufferpoolReuseBuffer(env.pool, received);
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
