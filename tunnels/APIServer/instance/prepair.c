#include "APIServer/structure.h"
#include "instance/startup.h"
#include "loggers/network_logger.h"

void apiserverOnPrepair(tunnel_t *t)
{
    apiserver_tstate_t *ts = tunnelGetState(t);
    /* Final pool padding is known now. Every possible handler worker must be
     * able to materialize one small result plus bounded parsing metadata. */
    for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
    {
        buffer_pool_fit_t fit;
        if (! bufferpoolQueryBestFit(getWorkerBufferPool(wid), kApiMinimumResultAllowance, 0, &fit) ||
            fit.allocation_charge > ts->limits.handler_working_memory - kApiHandlerMetadataAllowance)
        {
            LOGE("APIServer: handler_working_memory cannot accommodate a complete bounded result");
            startupFailureRecord(1);
            return;
        }
    }
    for (api_client_t *client = ts->clients; client; client = client->next)
        for (api_permission_t *p = client->permissions; p; p = p->next)
        {
            if (nodemanagerResolveApiTarget(p->config, p->node, &p->target, NULL) != kNodeApiTargetFound ||
                ! (p->descriptor = nodeApiFind(p->target, p->operation)))
            {
                LOGE("APIServer: allowlist must name an existing registered target operation");
                startupFailureRecord(1);
                return;
            }
        }
}
