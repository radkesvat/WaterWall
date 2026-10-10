/* Multi-config startup: all chains finalize padding before any prepare/start
 * callback. Real pool checkout in callbacks verifies the fixed inventory is
 * ready. Preparation failure starts no producers; shutdown stops later configs.
 * CTest: waterwall.node_manager_startup_unit. No sockets or worker loops run. */
#include "test_assert.h"
#include "wwapi.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned       created, prepared, started;
static bool           fail_prepare;
static unsigned       stop_phase;
static bool           stop_requested;
static buffer_pool_t *pool;

bool __wrap_applicationShutdownWasRequested(void);

bool __wrap_applicationShutdownWasRequested(void)
{
    return stop_requested;
}

static void probePrepare(tunnel_t *tunnel)
{
    discard tunnel;
    require(created == 4 && started == 0, "preparation preceded complete topology or followed a producer");
    require(bufferpoolGetSpliceBufferPadding(pool) == 160, "preparation observed partial chain padding");
#if WW_HAVE_SPLICE
    require(sbufSplicePoolPadding() == 160 && sbufSplicePoolCount() == 2, "inventory was not ready before preparation");
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL && buf->l_pad == 160, "preparation could not acquire a correctly padded splice buffer");
    bufferpoolReuseBuffer(pool, buf);
#endif
    if (++prepared == 3 && fail_prepare)
        startupFailureRecord(1);
    if (prepared == 2 && stop_phase == 1)
        stop_requested = true;
}

static void probeStart(tunnel_t *tunnel)
{
    discard tunnel;
    require(prepared == 4, "producer started before every configuration was prepared");
    if (++started == 2 && stop_phase == 2)
        stop_requested = true;
}

static tunnel_t *probeCreate(node_t *node)
{
    require(prepared == 0 && started == 0, "a previous configuration started during topology construction");
    const cJSON *padding        = cJSON_GetObjectItemCaseSensitive(node->node_settings_json, "padding");
    node->required_padding_left = padding != NULL ? (uint16_t) padding->valueint : 0;
    tunnel_t *tunnel            = tunnelCreate(node, 0, 0);
    require(tunnel != NULL, "probe construction failed");
    tunnel->onPrepare = probePrepare;
    tunnel->onStart   = probeStart;
    ++created;
    return tunnel;
}

static config_file_t *configCreate(unsigned padding)
{
    config_file_t *config = memoryAllocateZero(sizeof(*config));
    require(config != NULL && mutexTryInit(&config->guard), "config construction failed");
    config->file_path = stringDuplicate("startup-fixture.json");
    config->name      = stringDuplicate("startup-fixture");
    char json[512];
    snprintf(json,
             sizeof(json),
             "[{\"name\":\"head\",\"type\":\"StartupProbeHead\",\"next\":\"tail\",\"settings\":{\"padding\":%u}},"
             "{\"name\":\"tail\",\"type\":\"StartupProbeTail\",\"settings\":{}}]",
             padding);
    config->root  = cJSON_Parse(json);
    config->nodes = config->root;
    require(config->root != NULL, "config JSON construction failed");
    return config;
}

static void exerciseStartup(bool fail, unsigned stop)
{
    created = prepared = started = 0;
    fail_prepare                 = fail;
    stop_phase                   = stop;
    stop_requested               = false;
    GSTATE.ram_profile           = kRamProfileS1Memory;
    GSTATE.flag_initialized      = true;
    GSTATE.workers_count         = 1;
    master_pool_t *masters[3];
    for (unsigned i = 0; i < 3; ++i)
        masters[i] = masterpoolCreateWithCapacity(4);
    pool = bufferpoolCreate(masters[0], masters[1], masters[2], 4, 8192, 32768, 1024, 1048576, 8192);
    require(pool != NULL, "buffer pool construction failed");
    GSTATE.shortcut_buffer_pools = &pool;
    GSTATE.node_manager          = nodemanagerCreate();
    require(GSTATE.node_manager != NULL, "node manager construction failed");
#if WW_HAVE_SPLICE
    require(sbufSplicePoolPrepare(), "shared control publication failed");
#endif
    const char *types[] = {"StartupProbeHead", "StartupProbeTail"};
    for (unsigned i = 0; i < 2; ++i)
    {
        node_t node = {.type        = stringDuplicate(types[i]),
                       .hash_type   = calcHashBytes(types[i], strlen(types[i])),
                       .flags       = (i == 0 ? kNodeFlagChainHead : kNodeFlagChainEnd) | kNodeFlagSupportsSplice,
                       .layer_group = kNodeLayer4,
                       .layer_group_prev_node = i == 0 ? kNodeLayerNone : kNodeLayer4,
                       .layer_group_next_node = i == 0 ? kNodeLayer4 : kNodeLayerNone,
                       .can_have_next         = i == 0,
                       .can_have_prev         = i != 0,
                       .createHandle          = probeCreate};
        nodelibraryRegister(node);
    }
    require(wwStartupSucceeded(nodemanagerBuildConfigFile(configCreate(33))), "first configuration failed");
    require(bufferpoolGetSpliceBufferPadding(pool) == 64 && prepared == 0 && started == 0,
            "first configuration was started instead of staged");
    require(wwStartupSucceeded(nodemanagerBuildConfigFile(configCreate(129))), "second configuration failed");
    require(bufferpoolGetSpliceBufferPadding(pool) == 160 && prepared == 0 && started == 0,
            "second configuration failed to finalize global padding before startup");
#if WW_HAVE_SPLICE
    require(sbufSplicePoolInitialize(2ULL * 1024 * 1024, 4096, 2, 160) == 2, "inventory setup failed");
#endif
    const ww_startup_result_t result = nodemanagerStartConfigs();
    require(wwStartupSucceeded(result) == ! fail, "startup status lost preparation failure");
    const unsigned expected_started = fail || stop == 1 ? 0U : stop == 2 ? 2U : 4U;
    require(started == expected_started, "startup failure or shutdown request started a later configuration");
    if (stop != 0)
        require(stop_requested, "shutdown fixture did not request its stop");
    const ww_lifecycle_context_t context = {.scope        = kWwLifecycleProcessShutdown,
                                            .close_policy = kWwLifecycleCloseAbortive};
    nodemanagerStop(&context);
    nodemanagerDestroy();
    GSTATE.node_manager = NULL;
    nodelibraryCleanup();
    bufferpoolDestroy(pool);
    sbufSplicePoolDestroy();
    for (unsigned i = 0; i < 3; ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.workers_count         = 0;
    GSTATE.flag_initialized      = false;
}

int main(void)
{
    testCaseSet("node_manager_startup_test");
    exerciseStartup(false, 0);
    exerciseStartup(true, 0);
    exerciseStartup(false, 1);
    exerciseStartup(false, 2);
    return 0;
}
