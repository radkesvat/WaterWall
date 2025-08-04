#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *reverseclientTunnelCreate(node_t *node)
{

    int       wc = getWorkersCount() - WORKER_ADDITIONS;
    tunnel_t *t  = tunnelCreate(node, sizeof(reverseclient_tstate_t) + (wc * sizeof(reverseclient_thread_box_t)),
                                sizeof(reverseclient_lstate_t));

    t->fnInitU    = &reverseclientTunnelUpStreamInit;
    t->fnEstU     = &reverseclientTunnelUpStreamEst;
    t->fnFinU     = &reverseclientTunnelUpStreamFinish;
    t->fnPayloadU = &reverseclientTunnelUpStreamPayload;
    t->fnPauseU   = &reverseclientTunnelUpStreamPause;
    t->fnResumeU  = &reverseclientTunnelUpStreamResume;

    t->fnInitD    = &reverseclientTunnelDownStreamInit;
    t->fnEstD     = &reverseclientTunnelDownStreamEst;
    t->fnFinD     = &reverseclientTunnelDownStreamFinish;
    t->fnPayloadD = &reverseclientTunnelDownStreamPayload;
    t->fnPauseD   = &reverseclientTunnelDownStreamPause;
    t->fnResumeD  = &reverseclientTunnelDownStreamResume;

    t->onPrepair = &reverseclientTunnelOnPrepair;
    t->onStart   = &reverseclientTunnelOnStart;
    t->onDestroy = &reverseclientTunnelDestroy;

    const cJSON            *settings = node->node_settings_json;
    reverseclient_tstate_t *ts       = tunnelGetState(t);

    getIntFromJsonObject((int *) &(ts->min_unused_cons), settings, "minimum-unused");

    ts->min_unused_cons     = (uint32_t) min(max((getWorkersCount() * (ssize_t) 2), ts->min_unused_cons), 128);
    // ts->min_unused_cons     = 1;
    ts->starved_connections = idleTableCreate(getWorkerLoop(getWID()));
    return t;
}
