/* Explicit operations and exact loaded-target selection, including hash mismatch,
 * ambiguous unregistered duplicates, private children, name preparation policy,
 * rejected callback tables and final destruction. No network/worker loops.
 * CTest: waterwall.api_registry_resolver_unit. */
#include "wwapi.h"

#include "test_assert.h"

#include "managers/node_manager.c" // NOLINT: exercise private loaded maps and preparation validation

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static api_result_t unusedHandler(tunnel_t *target, sbuf_t *message, const node_api_call_context_t *context)
{
    discard target;
    discard context;
    return tunnelapiRecycleMessage(message);
}

static const node_api_operation_t operation = {.name                  = "status",
                                               .handler               = unusedHandler,
                                               .read_only             = true,
                                               .request_content_type  = "application/json",
                                               .response_content_type = "application/json",
                                               .response_encoding     = kNodeApiEncodingUtf8,
                                               .execution             = kNodeApiCallingWorker};

static char      name_one[]       = "one";
static char      name_two[]       = "two";
static char      name_duplicate[] = "duplicate";
static char      name_unique[]    = "unique";
static char      name_other[]     = "other-name";
static char      name_empty[]     = "";
static char      name_bad[]       = "bad-callback";
static tunnel_t *rejected_instance;
static tunnel_t *rejectedCreate(node_t *node)
{
    tunnel_t *tunnel = tunnelCreate(node, 0, 0);
    require(tunnel != NULL, "rejected fixture allocation failed");
    require(nodeApiRegister(tunnel, &operation, 1), "fixture registration failed");
    rejected_instance  = tunnel;
    tunnel->fnPayloadU = NULL;
    return tunnel;
}

static void testResolverAndRegistry(void)
{
    node_manager_t       *manager    = nodemanagerCreate();
    config_file_t         files[2]   = {{.name = name_one}, {.name = name_two}};
    node_manager_config_t configs[2] = {{.config_file = &files[0]}, {.config_file = &files[1]}};
    tunnel_t              first = {0}, second = {0}, third = {0};
    tunnel_t             *targets[3] = {&first, &second, &third};
    node_t                nodes[3]   = {{.name = name_duplicate, .instance = targets[0]},
                                        {.name = name_duplicate, .instance = targets[1]},
                                        {.name = name_unique, .instance = targets[2]}};
    for (size_t i = 0; i < 2; ++i)
    {
        configs[i].node_map = map_node_t_init();
        require(vec_configs_t_push(&manager->configs, &configs[i]) != NULL, "config publication failed");
    }
    map_node_t_insert(&configs[0].node_map, calcHashBytes("duplicate", 9), &nodes[0]);
    map_node_t_insert(&configs[1].node_map, calcHashBytes("duplicate", 9), &nodes[1]);
    map_node_t_insert(&configs[0].node_map, calcHashBytes("unique", 6), &nodes[2]);
    tunnel_t   *selected        = NULL;
    const char *resolved_config = NULL;
    require(nodeApiFind(targets[0], "status") == NULL, "API exposed without registration");
    require(nodeApiRegister(targets[0], &operation, 1), "explicit registration failed");
    require(! nodeApiRegister(targets[0], &operation, 1), "duplicate instance registration accepted");
    require(nodeApiFind(targets[0], "status") == &operation, "registered operation missing");
    require(nodeApiFind(targets[0], "Status") == NULL, "operation matching ignored case");
    require(nodemanagerResolveApiTarget(NULL, "duplicate", &selected, &resolved_config) == kNodeApiTargetAmbiguous,
            "unregistered duplicate did not preserve global ambiguity");
    require(nodemanagerResolveApiTarget("one", "duplicate", &selected, &resolved_config) == kNodeApiTargetFound &&
                selected == targets[0] && strcmp(resolved_config, "one") == 0,
            "qualified selection failed");
    require(nodemanagerResolveApiTarget(NULL, "unique", &selected, &resolved_config) == kNodeApiTargetFound &&
                selected == targets[2],
            "unqualified unique selection failed");
    require(nodemanagerResolveApiTarget(NULL, "private-child", &selected, NULL) == kNodeApiTargetNotFound,
            "private undeclared child became public");
    require(nodemanagerResolveApiTarget("file-path.json", "unique", &selected, NULL) == kNodeApiTargetNotFound,
            "file path was treated as a logical configuration");
    nodes[2].name = name_other;
    require(nodemanagerGetConfigNodeByName(&configs[0], "unique") == NULL,
            "hash-only match routed to a differently named node");
    nodes[2].name = name_unique;
    files[1].name = name_one;
    require(validateApiTargetNames(), "no-APIServer process gained new name restrictions");
    nodeApiRequireEnabled();
    require(! validateApiTargetNames(), "duplicate global config names were accepted");
    files[1].name = name_two;
    require(validateApiTargetNames(), "valid global names rejected");
    files[1].name = name_empty;
    require(! validateApiTargetNames(), "empty global configuration name accepted");
    nodeApiUnregister(targets[0]);
    require(! nodeApiHasRegistration(targets[0]), "unregister left a stale instance");
    for (size_t i = 0; i < 2; ++i)
        map_node_t_drop(&configs[i].node_map);
    vec_configs_t_clear(&manager->configs);
    nodemanagerDestroy();
}

static void testRejectedCallbackAndDestruction(void)
{
    nodemanagerCreate();
    node_t               node    = {.name = name_bad, .createHandle = rejectedCreate};
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    require(nodemanagerCreateTunnelInstance(&node) == NULL, "malformed callback table accepted");
    require(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "callback rejection lost startup failure");
    require(! nodeApiHasRegistration(rejected_instance), "callback rejection retained a freed registration");
    node_t *owned_node   = nodemanagerNewNode();
    owned_node->name     = stringDuplicate("owned");
    owned_node->instance = tunnelCreate(owned_node, 0, 0);
    require(nodeApiRegister(owned_node->instance, &operation, 1), "owned registration failed");
    tunnel_t *destroyed = owned_node->instance;
    nodemanagerDestroyNode(owned_node);
    require(! nodeApiHasRegistration(destroyed), "ordinary destruction retained a stale descriptor");
    nodemanagerDestroy();
}

int main(void)
{
    TEST_RUN_CASE(testResolverAndRegistry);
    TEST_RUN_CASE(testRejectedCallbackAndDestruction);
    return 0;
}
