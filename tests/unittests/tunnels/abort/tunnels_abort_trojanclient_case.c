/*
 * Covers: tunnels abort trojanclient case; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#include "TrojanClient/internal.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortTrojanClientUdpInitCase(void)
{
    // This valid line state previously absorbed the callback without terminating.
    tunnel_t *t = tunnelCreate(NULL, sizeof(trojanclient_tstate_t), sizeof(trojanclient_lstate_t));
    if (t == NULL)
    {
        return kAbortCaseAllocationFailed;
    }
    line_t *l = memoryAllocateCacheAlignedZero(sizeof(line_t) + t->lstate_size);
    if (l == NULL)
    {
        tunnelDestroy(t);
        return kAbortCaseAllocationFailed;
    }
    atomic_init(&l->refc, 1);
    l->alive                  = true;
    l->wid                    = 0;
    trojanclient_lstate_t *ls = lineGetState(l, t);
    ls->kind                  = kTrojanClientLineKindUdpApplication;
    t->fnInitD(t, l);

    memoryFreeAligned(l);
    tunnelDestroy(t);
    return 0;
}
