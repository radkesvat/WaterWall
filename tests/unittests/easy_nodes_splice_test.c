#include "buffer_disposal_probe.h"
#include "easy_nodes_splice_fixture.h"
#include "global_state.h"

static easy_fixture_t *fixture;
static atomic_uint     disposals;
#if WW_HAVE_SPLICE
static int watched_pipe = -1;
#endif

void easyRequire(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

void easyWatch(sbuf_t *buf)
{
    atomic_store(&disposals, 0);
#if WW_HAVE_SPLICE
    watched_pipe = sbufIsSplice(buf) ? dup(sbufSpliceMetadata(buf).pipefd[0]) : -1;
    easyRequire(! sbufIsSplice(buf) || watched_pipe >= 0, "duplicate disposal observation descriptor");
#endif
    watchBufferDisposal(buf, &disposals);
}

void easyRequireDisposed(void)
{
    easyRequire(atomic_load(&disposals) == 1, "buffer must be disposed exactly once");
#if WW_HAVE_SPLICE
    if (watched_pipe >= 0)
    {
        char    byte;
        ssize_t result = read(watched_pipe, &byte, 1);
        easyRequire(result == 0 || (result == -1 && errno == EAGAIN), "discard left bytes in private pipe");
        close(watched_pipe);
        watched_pipe = -1;
    }
#endif
}

sbuf_t *easyPayload(bool splice)
{
    buffer_pool_t *pool = getWorkerBufferPool(0);
    sbuf_t        *buf;
    if (splice)
    {
#if WW_HAVE_SPLICE
        buf = bufferpoolGetSpliceBuffer(pool);
        easyRequire(buf != NULL, "checkout real splice buffer");
        easyRequire(write(sbufSpliceMetadata(buf).pipefd[1], "body", 4) == 4, "populate private pipe");
        buf->capacity = buf->l_pad + 4;
        sbufSetLength(buf, 4);
#else
        easyRequire(false, "splice fixture on unsupported build");
        return NULL;
#endif
    }
    else
    {
        buf = bufferpoolGetSmallBuffer(pool);
        sbufSetLength(buf, 4);
        sbufWrite(buf, "body", 4);
    }
    sbufShiftLeft(buf, 3);
    sbufWrite(buf, "pre", 3);
    return buf;
}

void easyExpect(easy_fixture_t *f, sbuf_t *buf, const void *bytes, uint32_t length, uint32_t prefix)
{
    f->expected = buf;
    f->bytes    = bytes;
    f->length   = length;
    f->prefix   = prefix;
    f->splice   = sbufIsSplice(buf);
    if (f->splice)
        f->metadata = sbufSpliceMetadata(buf);
}

static void receive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    easy_fixture_t *f = fixture;
    easyRequire(l == f->line, "forwarding changed exact line identity");
    if (t == f->next)
        ++f->upstream;
    else
    {
        easyRequire(t == f->prev, "wrong callback destination");
        ++f->downstream;
    }
    if (buf == f->expected)
    {
        easyRequire(sbufIsSplice(buf) == f->splice, "forwarding changed representation");
        easyRequire(sbufGetLength(buf) == f->length, "logical length changed");
        easyRequire(sbufGetLeftCapacity(buf) >= 32, "onward padding lost");
        if (f->splice)
        {
            easyRequire(sbufGetResidentPrefixLength(buf) == f->prefix, "pipe body was materialized");
            splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
            easyRequire(metadata.pipefd[0] == f->metadata.pipefd[0] && metadata.pipefd[1] == f->metadata.pipefd[1] &&
                            metadata.pipe_capacity == f->metadata.pipe_capacity &&
                            metadata.capacity_retry_at_us == f->metadata.capacity_retry_at_us,
                        "private pipe metadata changed");
        }
        uint8_t bytes[256];
        easyRequire(f->length <= sizeof(bytes), "test payload too large");
        sbufReadRangeToMemory(buf, bytes, f->length);
        easyRequire(memcmp(bytes, f->bytes, f->length) == 0, "prefix/body bytes changed");
        f->expected = NULL;
    }
    else
    {
        easyRequire(! sbufIsSplice(buf), "generated junk must be ordinary");
        easyRequire(f->upstream == 1 && f->downstream == 0, "junk must precede application payload");
        easyRequire(sbufGetLength(buf) > 0, "generated junk is empty");
    }
    lineReuseBuffer(l, buf);
    if (f->close_on_payload)
    {
        f->node->fnFinD(f->node, l);
    }
}
static void finish(tunnel_t *t, line_t *l)
{
    ++fixture->finishes;
    if (t == fixture->prev)
    {
        lineDestroy(l);
        fixture->line = NULL;
    }
}
static void init(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}
static void established(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++fixture->established;
}

void easySetup(easy_fixture_t *f, tunnel_t *node)
{
    memoryZero(f, sizeof(*f));
    fixture = f;
    f->node = node;
    easyRequire(node != NULL, "create tested tunnel");
    f->prev = tunnelCreate(NULL, 0, 0);
    f->next = tunnelCreate(NULL, 0, 0);
    easyRequire(f->prev && f->next, "create endpoint fixtures");
    f->prev->fnPayloadD = f->next->fnPayloadU = receive;
    f->prev->fnFinD = f->next->fnFinU = finish;
    f->prev->fnInitD = f->next->fnInitU = init;
    f->prev->fnEstD                     = established;
    tunnelBind(f->prev, node);
    tunnelBind(node, f->next);
    f->chain                      = tunnelchainCreate(1);
    f->chain->sum_line_state_size = node->lstate_size;
    node->chain                   = f->chain;
    tunnelchainFinalize(f->chain);
    f->line = lineCreate(tunnelchainGetLinePools(f->chain), 0);
}
void easyTeardown(easy_fixture_t *f)
{
    if (f->line)
    {
        memoryZero(lineGetState(f->line, f->node), f->node->lstate_size);
        lineDestroy(f->line);
    }
    tunnelchainDestroy(f->chain);
    tunnelDestroy(f->prev);
    tunnelDestroy(f->next);
    tunnelDestroy(f->node);
    fixture = NULL;
}

int main(void)
{
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 1;
    data.ram_profile                    = kRamProfileS1Memory;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = data.core_logger_data.log_level = off;
    data.network_logger_data.log_level = data.dns_logger_data.log_level = off;
    easyRequire(wwStartupSucceeded(createGlobalState(data)), "initialize runtime");
    globalstateUpdateAllocationPadding(192);
    for (unsigned splice = 0; splice <= WW_HAVE_SPLICE; ++splice)
    {
        testHeaderSplice(splice);
        testBridgeAndBlackHoleSplice(splice);
        testUserControllerSplice(splice);
        testJunkSplice(splice);
    }
    worker_t                     *worker  = getWorker(0);
    const ww_lifecycle_context_t *context = wwLifecycleProcessShutdown();
    easyRequire(workerInstallApplicationQuiesceRequest(worker, context) != kWorkerQuiesceRequestUnavailable, "quiesce");
    workerPerformQuiesce(worker, context);
    easyRequire(workerRequestDrain(worker), "request drain");
    workerPerformDrain(worker, context);
    easyRequire(workerRequestTeardown(worker), "request teardown");
    workerPerformTeardown(worker);
    workerDestroyPseudoWorkerResources(getWorker(getTotalWorkersCount() - 1));
    destroyGlobalState();
    puts("easy node ordinary/splice payload tests passed");
}
