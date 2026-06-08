#include "structure.h"

#include "loggers/network_logger.h"

static bool keepaliveclientLoadPingInterval(keepaliveclient_tstate_t *ts, const cJSON *settings)
{
    int ping_interval_ms = kKeepAliveDefaultPingMs;

    if (settings != NULL)
    {
        getIntFromJsonObjectOrDefault(&ping_interval_ms, settings, "ping-interval", kKeepAliveDefaultPingMs);
    }

    if (ping_interval_ms < 1)
    {
        LOGF("JSON Error: KeepAliveClient->settings->ping-interval (int field) : expected a value >= 1");
        return false;
    }

    ts->ping_interval_ms = (uint32_t) ping_interval_ms;
    return true;
}

tunnel_t *keepaliveclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(keepaliveclient_tstate_t), sizeof(keepaliveclient_lstate_t));
    keepaliveclient_tstate_t *ts = tunnelGetState(t);

    t->fnInitU    = &keepaliveclientTunnelUpStreamInit;
    t->fnEstU     = &keepaliveclientTunnelUpStreamEst;
    t->fnFinU     = &keepaliveclientTunnelUpStreamFinish;
    t->fnPayloadU = &keepaliveclientTunnelUpStreamPayload;
    t->fnPauseU   = &keepaliveclientTunnelUpStreamPause;
    t->fnResumeU  = &keepaliveclientTunnelUpStreamResume;

    t->fnInitD    = &keepaliveclientTunnelDownStreamInit;
    t->fnEstD     = &keepaliveclientTunnelDownStreamEst;
    t->fnFinD     = &keepaliveclientTunnelDownStreamFinish;
    t->fnPayloadD = &keepaliveclientTunnelDownStreamPayload;
    t->fnPauseD   = &keepaliveclientTunnelDownStreamPause;
    t->fnResumeD  = &keepaliveclientTunnelDownStreamResume;

    t->onPrepare = &keepaliveclientTunnelOnPrepair;
    t->onStart   = &keepaliveclientTunnelOnStart;
    t->onStop    = &keepaliveclientTunnelOnStop;
    t->onDestroy = &keepaliveclientTunnelDestroy;

    mutexInit(&ts->lines_mutex);
    ts->lines_head       = NULL;
    ts->ping_interval_ms = kKeepAliveDefaultPingMs;

    if (! keepaliveclientLoadPingInterval(ts, node->node_settings_json))
    {
        keepaliveclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}
