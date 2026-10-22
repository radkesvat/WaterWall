#include "structure.h"

void quicclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    quicCloseAdmission(t);
}

void quicclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    quicQuiesceWorker(t, wid);
}
