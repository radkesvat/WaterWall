/*
 * Covers: tunnels abort httpclient case; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#include "wwapi.h"

#include "tunnels_abort_runtime_cases.h"

tunnel_t *httpclientTunnelCreate(node_t *node);

static void acceptFormerForward(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static int rejectReverseLifecycle(bool upstream)
{
    cJSON *settings = cJSON_Parse("{\"host\":\"http1.example.test\",\"path\":\"/ww/http1\",\"scheme\":\"http\","
                                  "\"port\":20500,\"method\":\"POST\",\"http-version\":\"1.1\"}");
    if (settings == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = httpclientTunnelCreate(&node);
    if (t == NULL)
    {
        cJSON_Delete(settings);
        return kAbortCaseAllocationFailed;
    }
    // Previously both callbacks forwarded here and returned normally.
    tunnel_t neighbor = {.fnEstU = acceptFormerForward, .fnInitD = acceptFormerForward};
    t->next           = &neighbor;
    t->prev           = &neighbor;
    if (upstream)
    {
        t->fnEstU(t, NULL);
    }
    else
    {
        t->fnInitD(t, NULL);
    }
    t->onDestroy(t, wwLifecycleStartupRollback());
    cJSON_Delete(settings);
    return 0;
}

int tunnelsAbortHttpClientUpstreamEstCase(void)
{
    return rejectReverseLifecycle(true);
}

int tunnelsAbortHttpClientDownstreamInitCase(void)
{
    return rejectReverseLifecycle(false);
}
