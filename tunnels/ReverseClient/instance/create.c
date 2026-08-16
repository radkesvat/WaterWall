#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *reverseclientTunnelCreate(node_t *node)
{

    int       wc = getWorkersCount();
    tunnel_t *t  = tunnelCreate(node,
                               sizeof(reverseclient_tstate_t) + (wc * sizeof(reverseclient_thread_box_t)),
                               sizeof(reverseclient_lstate_t));
    if (! t)
    {
        return NULL;
    }

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

    t->onPrepare        = &reverseclientTunnelOnPrepair;
    t->onStart          = &reverseclientTunnelOnStart;
    t->onQuiesceRequest = &reverseclientTunnelOnQuiesceRequest;
    t->onWorkerStop     = &reverseclientTunnelOnWorkerStop;
    t->onStop           = &reverseclientTunnelOnStop;
    t->onDestroy        = &reverseclientTunnelDestroy;

    const cJSON            *settings = node->node_settings_json;
    reverseclient_tstate_t *ts       = tunnelGetState(t);
    atomic_init(&ts->stopping, false);

    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: ReverseClient->settings (object field) : expected an object");
        tunnelDestroy(t);
        return NULL;
    }

    if (! reverseclientHandshakeBuildFromSettings(
            settings, "ReverseClient", &ts->handshake_bytes, &ts->handshake_length))
    {
        tunnelDestroy(t);
        return NULL;
    }

    int min_unused = 0;
    if (! getIntFromJsonObject(&min_unused, settings, "minimum-unused"))
    {
        ts->min_unused_cons = (uint32_t) getWorkersCount() * 4U;
    }
    else
    {
        if (min_unused <= 0)
        {
            LOGF("ReverseClient: minimum-unused must be greater than 0, got %d", min_unused);
            reverseclientHandshakeDestroy(ts->handshake_bytes);
            tunnelDestroy(t);
            return NULL;
        }
        ts->min_unused_cons = (uint32_t) min_unused;
    }

    // ts->min_unused_cons     = 1;

    /*
     * The starved-connection table is created during main-thread configuration,
     * so it is structurally owned by worker 0: its sweep timer runs on worker 0's
     * loop, and idle_table_t already dispatches each expiry to the item's own
     * worker through the worker-message queue. Say worker 0 explicitly rather
     * than inheriting whatever WID the creating thread happens to carry.
     */
    if (UNLIKELY(! currentThreadIsEventWorkerWID(0)))
    {
        LOGF("ReverseClient: node creation must run on worker 0, caller worker: %d", workerWIDForLog(getWID()));
        reverseclientHandshakeDestroy(ts->handshake_bytes);
        tunnelDestroy(t);
        return NULL;
    }

    ts->starved_connections = idleTableCreate(getWorkerLoop(0));
    return t;
}
