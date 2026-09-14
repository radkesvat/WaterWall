#include "structure.h"

void httpproxyserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard       context;
    hps_tstate_t *ts = tunnelGetState(t);
    if (ts->controller)
        tunnelOwnedChildDestroy(ts->controller);
    memoryFree(ts->controller_node.name);
    memoryFree(ts->controller_node.type);
    memoryFree(ts->controller_node.next);
    if (ts->users)
    {
        memoryZero(ts->users, ts->user_count * sizeof(*ts->users));
        memoryFree(ts->users);
    }
    if (ts->workers)
    {
        for (unsigned i = 0; i < ts->worker_count; ++i)
        {
            assert(! ts->workers[i].children);
            assert(! ts->workers[i].timers);
        }
        memoryFree(ts->workers);
    }
    tunnelDestroy(t);
}
