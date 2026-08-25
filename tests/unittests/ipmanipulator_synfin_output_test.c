#include "IpManipulator/structure.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kTestPacketCount = 5
};

typedef void (*synfinsnitrick_test_recycle_hook_t)(sbuf_t *buf);

void    ipmanipulatorSynfinTestSetRecycleHook(synfinsnitrick_test_recycle_hook_t hook);
void    ipmanipulatorSynfinTestSendOutputs(tunnel_t *t, line_t *l, sbuf_t **packets, uint16_t count);
sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length);

static master_pool_t *large_master;
static master_pool_t *small_master;
static buffer_pool_t *buffer_pool;
static uint8_t        emitted_ids[kTestPacketCount];
static uint8_t        recycled_ids[kTestPacketCount];
static uint8_t        seen_ids[UINT8_MAX + 1U];
static uint16_t       emitted_count;
static uint16_t       recycled_count;
static uint16_t       kill_after_count;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint8_t packetId(const sbuf_t *buf)
{
    require(buf != NULL && sbufGetLength((sbuf_t *) buf) == 1U, "invalid Synfin output test packet");
    return *((const uint8_t *) sbufGetRawPtr((sbuf_t *) buf));
}

static void recordBuffer(uint8_t id)
{
    require(seen_ids[id] == 0, "a Synfin output buffer was consumed more than once");
    seen_ids[id] = 1;
}

static void captureUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;

    uint8_t id = packetId(buf);
    require(emitted_count < ARRAY_SIZE(emitted_ids), "Synfin emitted packet capture overflow");
    recordBuffer(id);
    emitted_ids[emitted_count++] = id;
    lineReuseBuffer(l, buf);

    if (kill_after_count != 0 && emitted_count == kill_after_count)
    {
        /* Model a re-entrant downstream close while the outer line reference remains held. */
        l->alive = false;
    }
}

static void captureRecycle(sbuf_t *buf)
{
    uint8_t id = packetId(buf);
    require(recycled_count < ARRAY_SIZE(recycled_ids), "Synfin recycle capture overflow");
    recordBuffer(id);
    recycled_ids[recycled_count++] = id;
}

void ipmanipulatorEmitUpstream(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    forward(t, l, buf);
}

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len)
{
    discard l;
    discard buf;
    discard new_len;
    return NULL;
}

bool parseClientHelloSni(const uint8_t *packet, uint32_t packet_length, sni_match_t *match)
{
    discard packet;
    discard packet_length;
    discard match;
    return false;
}

sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length)
{
    discard instance;
    discard caller_line;
    discard hostname;
    discard hostname_length;
    return NULL;
}

static void initializeEnvironment(void)
{
    large_master = masterpoolCreateWithCapacity(32);
    small_master = masterpoolCreateWithCapacity(32);
    buffer_pool  = bufferpoolCreate(large_master, small_master, 16, 4096, 256);

    GSTATE.shortcut_buffer_pools         = &buffer_pool;
    GSTATE.masterpool_buffer_pools_large = large_master;
    GSTATE.masterpool_buffer_pools_small = small_master;
    GSTATE.workers_count                 = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);
}

static void destroyEnvironment(void)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(buffer_pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
}

static void initializeLine(line_t *line)
{
    memoryZero(line, sizeof(*line));
    atomicStoreRelaxed(&line->refc, 1);
    line->alive = true;
    line->wid   = 0;
}

static sbuf_t *makePacket(uint8_t id)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(buffer_pool);
    sbufSetLength(buf, 1);
    *((uint8_t *) sbufGetMutablePtr(buf)) = id;
    return buf;
}

static void resetCapture(uint16_t kill_after)
{
    memoryZero(emitted_ids, sizeof(emitted_ids));
    memoryZero(recycled_ids, sizeof(recycled_ids));
    memoryZero(seen_ids, sizeof(seen_ids));
    emitted_count    = 0;
    recycled_count   = 0;
    kill_after_count = kill_after;
}

static void runSequence(tunnel_t *t, line_t *line, uint8_t first_id)
{
    sbuf_t *packets[kTestPacketCount];
    for (uint16_t i = 0; i < ARRAY_SIZE(packets); ++i)
    {
        packets[i] = makePacket((uint8_t) (first_id + i));
    }

    ipmanipulatorSynfinTestSendOutputs(t, line, packets, ARRAY_SIZE(packets));
    for (uint16_t i = 0; i < ARRAY_SIZE(packets); ++i)
    {
        require(packets[i] == NULL, "the Synfin output helper retained an emitted packet");
        require(seen_ids[first_id + i] == 1, "a Synfin output packet was leaked");
    }
}

static void testSynchronousSequenceOrder(tunnel_t *t)
{
    line_t line;
    initializeLine(&line);
    resetCapture(0);

    runSequence(t, &line, 1);

    require(lineIsAlive(&line), "the live Synfin sequence unexpectedly closed its line");
    require(emitted_count == kTestPacketCount && recycled_count == 0,
            "the live Synfin sequence did not emit every packet synchronously");
    for (uint16_t i = 0; i < kTestPacketCount; ++i)
    {
        require(emitted_ids[i] == i + 1U, "the Synfin sequence was emitted out of order");
    }
}

static void testLineDeathRecyclesRemainder(tunnel_t *t)
{
    line_t line;
    initializeLine(&line);
    resetCapture(2);

    runSequence(t, &line, 10);

    require(! lineIsAlive(&line), "the Synfin close fixture did not mark the line dead");
    require(emitted_count == 2 && emitted_ids[0] == 10 && emitted_ids[1] == 11,
            "Synfin emitted packets after the forwarding callback closed the line");
    require(recycled_count == 3 && recycled_ids[0] == 12 && recycled_ids[1] == 13 && recycled_ids[2] == 14,
            "Synfin did not recycle the unsent sequence tail exactly once and in order");
}

int main(void)
{
    initializeEnvironment();

    node_t    node = {.name = (char *) "ipmanipulator-synfin-output-test", .type = (char *) "TestTunnel"};
    tunnel_t *t    = tunnelCreate(&node, 0, 0);
    tunnel_t *sink = tunnelCreate(&node, 0, 0);
    require(t != NULL && sink != NULL, "failed to create Synfin output test tunnels");
    t->next          = sink;
    sink->prev       = t;
    sink->fnPayloadU = captureUpstream;

    ipmanipulatorSynfinTestSetRecycleHook(captureRecycle);
    testSynchronousSequenceOrder(t);
    testLineDeathRecyclesRemainder(t);
    ipmanipulatorSynfinTestSetRecycleHook(NULL);

    tunnelDestroy(sink);
    tunnelDestroy(t);
    destroyEnvironment();
    printf("ALL unit tests passed!\n");
    return 0;
}
