#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    reverseclient_tstate_t *ts  = tunnelGetState(t);
    reverseclient_lstate_t *dls = lineGetState(l, t);

    wid_t wid = lineGetWID(l);

    line_t* ul = dls->u;
    line_t* dl = dls->d;

    tunnelNextUpStreamFinish(t, ul);

    reverseclientLinestateDestroy(lineGetState(ul, t));
    reverseclientLinestateDestroy(dls);

    lineDestroy(ul);
    lineDestroy(dl);

    atomicDecRelaxed(&ts->reverse_cons);
    LOGD("ReverseClient: disconnected, tid: %d unused: %u active: %d",wid,
         ts->threadlocal_pool[wid].unused_cons_count, atomicLoadRelaxed(&ts->reverse_cons));

   reverseclientInitiateConnectOnWorker(t, wid, false);
}
