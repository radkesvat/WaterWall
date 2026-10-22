#include "APIServer/structure.h"

void apiserverOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    apiserver_tstate_t *ts = tunnelGetState(t);
    atomic_store(&ts->stopping, true);
    nodeApiDomainClose(ts->domain);
    nodeApiDomainClose(ts->unauthenticated_domain);
}

void apiserverOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadOwnsWorker(wid));
    apiserver_tstate_t *ts = tunnelGetState(t);
    for (apiserver_lstate_t *ls = ts->sessions[wid]; ls; ls = ls->next)
    {
        ls->quiesced = true;
        if (ls->timer)
        {
            weventSetUserData(ls->timer, NULL);
            wtimerDelete(ls->timer);
            ls->timer = NULL;
        }
        apiserverAbandonJob(ls);
    }
}
