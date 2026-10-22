#include "APIServer/structure.h"

void apiserverDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    apiserver_tstate_t *ts = tunnelGetState(t);
    assert(atomic_load(&ts->session_count) == 0);
    if (ts->domain)
        nodeApiDomainDestroy(ts->domain);
    if (ts->unauthenticated_domain)
        nodeApiDomainDestroy(ts->unauthenticated_domain);
    memoryFree(ts->sessions);
    apiserverFreeSettings(ts);
    tunnelDestroy(t);
}
