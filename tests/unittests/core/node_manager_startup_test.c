/* Multi-config startup: all chains finalize padding before any prepare/start
 * callback. Real pool checkout in callbacks verifies the lazy inventory is
 * configured before first demand. Preparation failure starts no producers; shutdown stops later configs.
 * Portable input hints fail before any probe construction and a resolved profile starts normally.
 * CTest: waterwall.node_manager_startup_unit. No sockets or worker loops run. */
#include "wwapi.h"

#include "imported_tunnels.h"
#include "loggers/internal_logger.h"
#include "node_builder/config_policy.h"
#include "test_assert.h"
#ifdef WW_TEST_BLACKHOLE_SINK
#include "BlackHole/interface.h"
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static unsigned       created, prepared, started;
static bool           fail_prepare;
static unsigned       stop_phase;
static bool           stop_requested;
static buffer_pool_t *pool;

static char   diagnostic[2048];
static size_t diagnostic_length;

static void captureDiagnostic(int level, const char *buffer, int length)
{
    if (level != LOG_LEVEL_FATAL || length <= 0)
    {
        return;
    }
    const size_t count = min((size_t) length, sizeof(diagnostic) - diagnostic_length - 1);
    memoryCopy(diagnostic + diagnostic_length, buffer, count);
    diagnostic_length += count;
    diagnostic[diagnostic_length] = '\0';
}

static void clearDiagnostic(void)
{
    diagnostic_length = 0;
    diagnostic[0]     = '\0';
}

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
    require(sbufSplicePoolPadding() == 160 && sbufSplicePoolCapacityLimit() == 2ULL * 1024 * 1024,
            "inventory was not configured before preparation");
    if (prepared == 0)
        require(sbufSplicePoolCount() == 0 && sbufSplicePoolCapacity() == 0,
                "inventory allocated pipes before first demand");
    sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
    require(buf != NULL && buf->initial_headroom == 160,
            "preparation could not acquire a correctly padded splice buffer");
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

static config_file_t *configCreate(const char *json)
{
    config_file_t *config = memoryAllocateZero(sizeof(*config));
    require(config != NULL && mutexTryInit(&config->guard), "config construction failed");
    config->file_path = stringDuplicate("startup-fixture.json");
    config->name      = stringDuplicate("startup-fixture");
    config->root      = cJSON_Parse(json);
    config->nodes     = config->root;
    require(config->root != NULL, "config JSON construction failed");
    return config;
}

static config_file_t *configCreateWithPadding(unsigned padding)
{
    char json[512];
    snprintf(json,
             sizeof(json),
             "[{\"name\":\"head\",\"type\":\"StartupProbeHead\",\"next\":\"tail\",\"settings\":{\"padding\":%u}},"
             "{\"name\":\"tail\",\"type\":\"StartupProbeTail\",\"settings\":{}}]",
             padding);
    return configCreate(json);
}

static void registerProbeTypes(void)
{
    const char *types[] = {"StartupProbeHead", "StartupProbeTail"};
    for (unsigned i = 0; i < ARRAY_SIZE(types); ++i)
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
}

static config_file_t *hintFixture(const char *sink_type, const char *hint_type, const char *hint_fields,
                                  bool hint_first)
{
    char sink[128];
    snprintf(sink, sizeof(sink), "{\"name\":\"sink\",\"type\":\"%s\"}", sink_type);
    char hint[256];
    snprintf(hint, sizeof(hint), "{\"name\":\"entry\",\"type\":\"%s\"%s}", hint_type, hint_fields);
    char json[512];
    snprintf(json, sizeof(json), "[%s,%s]", hint_first ? hint : sink, hint_first ? sink : hint);
    return configCreate(json);
}

static void exerciseStartup(bool fail, unsigned stop, bool resolve_hint)
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
    registerProbeTypes();
    config_file_t *first;
    if (resolve_hint)
    {
        first        = hintFixture("StartupProbeTail", "HintConnectionIN", ",\"next\":\"sink\",\"settings\":{}", false);
        cJSON *entry = cJSON_GetArrayItem(first->nodes, 1);
        require(cJSON_ReplaceItemInObjectCaseSensitive(entry, "type", cJSON_CreateString("StartupProbeHead")),
                "concrete input replacement failed");
        require(cJSON_AddNumberToObject(cJSON_GetObjectItemCaseSensitive(entry, "settings"), "padding", 33) != NULL,
                "concrete input settings construction failed");
    }
    else
    {
        first = configCreateWithPadding(33);
    }
    require(wwStartupSucceeded(nodemanagerBuildConfigFile(first)), "first configuration failed");
    require(bufferpoolGetSpliceBufferPadding(pool) == 64 && prepared == 0 && started == 0,
            "first configuration was started instead of staged");
    require(wwStartupSucceeded(nodemanagerBuildConfigFile(configCreateWithPadding(129))),
            "second configuration failed");
    require(bufferpoolGetSpliceBufferPadding(pool) == 160 && prepared == 0 && started == 0,
            "second configuration failed to finalize global padding before startup");
#if WW_HAVE_SPLICE
    require(sbufSplicePoolInitialize(2ULL * 1024 * 1024, 4096, 2, 160), "inventory setup failed");
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

static void requireRejectedHint(config_file_t *config, const char *expected)
{
    clearDiagnostic();
    require(! wwStartupSucceeded(nodemanagerBuildConfigFile(config)), "input hint unexpectedly built");
    require(strstr(diagnostic, expected) != NULL, diagnostic);
    require(strstr(diagnostic, "create() returned NULL handle") == NULL, "manager called the refusal constructor");
    require(created == 0, "manager constructed a tunnel before rejecting the input hint");
}

static void exerciseInputHintRejections(logger_t *logger)
{
    static const char *types[]    = {"HintConnectionIN", "HintPacketIN"};
    static const char *messages[] = {
        "HintConnectionIN requires a connection input. Replace this hint with a concrete input before starting "
        "WaterWall.",
        "HintPacketIN requires a packet input. Replace this hint with a concrete input before starting WaterWall.",
    };
    loggerSetHandler(logger, captureDiagnostic);
    configPolicyRestrict(); // Built-in lookups must succeed with dynamic loading disabled.
    require(wwStartupSucceeded(loadImportedTunnelsIntoCore()), "load built-in node registry");
    GSTATE.node_manager = nodemanagerCreate();
    require(GSTATE.node_manager != NULL, "node manager construction failed");
    created = prepared = started = 0;
    registerProbeTypes();

    const char *sink_type = "StartupProbeTail";
#ifdef WW_TEST_BLACKHOLE_SINK
    node_t sink = nodeBlackHoleGet();
    sink_type   = sink.type;
    // Retain BlackHole's link metadata while counting any premature construction.
    sink.createHandle = probeCreate;
    nodelibraryRegister(sink);
#endif

    for (unsigned i = 0; i < ARRAY_SIZE(types); ++i)
    {
        node_t node = nodelibraryLoadByTypeName(types[i]);
        require(node.type != NULL && strcmp(node.type, types[i]) == 0 && node.createHandle != NULL,
                "input hint missing from the built-in registry");
        static const char *fields[] = {",\"next\":\"sink\"", ",\"next\":\"sink\",\"settings\":{}"};
        for (unsigned j = 0; j < ARRAY_SIZE(fields); ++j)
        {
            requireRejectedHint(hintFixture(sink_type, types[i], fields[j], true), messages[i]);
            requireRejectedHint(hintFixture(sink_type, types[i], fields[j], false), messages[i]);
        }
        clearDiagnostic();
        ww_startup_context_t startup = {0};
        wwStartupContextBegin(&startup);
        require(node.createHandle(&node) == NULL, "direct hint construction unexpectedly succeeded");
        require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "direct hint construction lost startup failure");
        require(strstr(diagnostic, messages[i]) != NULL, diagnostic);

        clearDiagnostic();
        require(node.createHandle(&node) == NULL, "hint construction without a startup context unexpectedly succeeded");
        require(strstr(diagnostic, messages[i]) != NULL, diagnostic);
    }

    requireRejectedHint(hintFixture(sink_type, types[0], "", false), "requires a next node");
    requireRejectedHint(hintFixture(sink_type, types[0], ",\"next\":\"private-successor\"", false), "could not find");
    require(strstr(diagnostic, "private-successor") == NULL, "restricted link error disclosed the successor name");
    requireRejectedHint(hintFixture(sink_type, types[1], ",\"next\":\"sink\",\"settings\":{\"unused\":true}", false),
                        "settings must be omitted or an empty object");
    requireRejectedHint(hintFixture(sink_type, types[1], ",\"next\":\"sink\",\"settings\":[]", false),
                        "settings must be omitted or an empty object");
    requireRejectedHint(
        configCreate("[{\"name\":\"private-predecessor\",\"type\":\"StartupProbeHead\",\"next\":\"private-entry\"},"
                     "{\"name\":\"private-entry\",\"type\":\"HintConnectionIN\",\"next\":\"sink\"},"
                     "{\"name\":\"sink\",\"type\":\"StartupProbeTail\"}]"),
        "must be a chain head");
    require(strstr(diagnostic, "private-predecessor") == NULL && strstr(diagnostic, "private-entry") == NULL,
            "restricted placement error disclosed node names");

    nodemanagerDestroy();
    GSTATE.node_manager = NULL;
    nodelibraryCleanup();
}

int main(void)
{
    testCaseSet("node_manager_startup_test");
    logger_t *logger = createInternalLogger(NULL, true);
    require(logger != NULL, "create startup diagnostic logger");
    exerciseStartup(false, 0, false);
    exerciseStartup(true, 0, false);
    exerciseStartup(false, 1, false);
    exerciseStartup(false, 2, false);
    exerciseStartup(false, 0, true);
    exerciseInputHintRejections(logger);
    internaloggerDestroy();
    return 0;
}
