#include "IpManipulator/interface.h"
#include "IpManipulator/structure.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static cJSON *createSettings(const char *sni)
{
    cJSON *settings = cJSON_CreateObject();
    require(settings != NULL && cJSON_AddStringToObject(settings, "synfin-sni", sni) != NULL,
            "failed to build IpManipulator test settings");
    return settings;
}

static tunnel_t *createManipulator(node_t *node, const char *name, const char *sni)
{
    *node                    = nodeIpManipulatorGet();
    node->name               = stringDuplicate(name);
    node->next               = stringDuplicate("normal-next");
    node->hash_name          = calcHashBytes(node->name, stringLength(node->name));
    node->hash_next          = calcHashBytes(node->next, stringLength(node->next));
    node->node_settings_json = createSettings(sni);

    tunnel_t *t = ipmanipulatorCreate(node);
    require(t != NULL, "failed to create IpManipulator with a private TlsClient child");
    node->instance = t;
    return t;
}

static void destroyManipulator(node_t *node)
{
    node->instance->onDestroy(node->instance, wwLifecycleStartupRollback());
    node->instance = NULL;
    cJSON_Delete(node->node_settings_json);
    memoryFree(node->name);
    memoryFree(node->type);
    memoryFree(node->next);
    memoryZero(node, sizeof(*node));
}

static void requirePrivateChild(tunnel_t *t, const char *expected_name, const char *expected_sni)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    const cJSON            *sni   = cJSON_GetObjectItemCaseSensitive(state->internal_tls_client_settings, "sni");

    require(state->internal_tls_client_tunnel != NULL, "IpManipulator did not create its internal TlsClient");
    require(state->trick_synfin_sni_tls_client_tunnel == state->internal_tls_client_tunnel,
            "synfin-sni did not retain the private TlsClient tunnel");
    require(state->internal_tls_client_node.instance == state->internal_tls_client_tunnel,
            "the private child node and tunnel instance disagree");
    require(state->internal_tls_client_tunnel->node == &state->internal_tls_client_node,
            "the private TlsClient does not reference its parent-owned child node");
    require(stringCompare(state->internal_tls_client_node.name, expected_name) == 0,
            "the private child name is not derived from its owning IpManipulator");
    require(cJSON_IsString(sni) && stringCompare(sni->valuestring, expected_sni) == 0,
            "structured child settings did not preserve the exact SNI");
}

int main(void)
{
    static const char special_sni[]       = "quote\"-slash\\-line\n.example";
    const uint32_t    saved_workers_count = GSTATE.workers_count;
    node_t            first               = {0};
    node_t            second              = {0};

    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);

    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
    require(frandGlobalInit(), "fast random initialization failed");
    frandInit();

    tunnel_t               *first_t      = createManipulator(&first, "ipm-first", special_sni);
    tunnel_t               *second_t     = createManipulator(&second, "ipm-second", special_sni);
    ipmanipulator_tstate_t *first_state  = tunnelGetState(first_t);
    ipmanipulator_tstate_t *second_state = tunnelGetState(second_t);

    requirePrivateChild(first_t, "ipm-first.synfin-sni-tls-client", special_sni);
    requirePrivateChild(second_t, "ipm-second.synfin-sni-tls-client", special_sni);
    require(stringCompare(first_state->internal_tls_client_node.name, second_state->internal_tls_client_node.name) != 0,
            "two parent nodes with the same SNI received colliding child names");

    destroyManipulator(&first);
    destroyManipulator(&second);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    return 0;
}
