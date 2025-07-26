#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *muxclientTunnelCreate(node_t *node)
{
    int wc = getWorkersCount() - WORKER_ADDITIONS;

    tunnel_t *t = tunnelCreate(node, sizeof(muxclient_tstate_t) + (wc * sizeof(line_t *)), sizeof(muxclient_lstate_t));

    t->fnInitU    = &muxclientTunnelUpStreamInit;
    t->fnEstU     = &muxclientTunnelUpStreamEst;
    t->fnFinU     = &muxclientTunnelUpStreamFinish;
    t->fnPayloadU = &muxclientTunnelUpStreamPayload;
    t->fnPauseU   = &muxclientTunnelUpStreamPause;
    t->fnResumeU  = &muxclientTunnelUpStreamResume;

    t->fnInitD    = &muxclientTunnelDownStreamInit;
    t->fnEstD     = &muxclientTunnelDownStreamEst;
    t->fnFinD     = &muxclientTunnelDownStreamFinish;
    t->fnPayloadD = &muxclientTunnelDownStreamPayload;
    t->fnPauseD   = &muxclientTunnelDownStreamPause;
    t->fnResumeD  = &muxclientTunnelDownStreamResume;

    t->onPrepair = &muxclientTunnelOnPrepair;
    t->onStart   = &muxclientTunnelOnStart;
    t->onDestroy = &muxclientTunnelDestroy;

    const cJSON        *settings = node->node_settings_json;
    muxclient_tstate_t *ts       = tunnelGetState(t);

    ts->concurrency_mode = parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "timer", "counter").status;

    if (ts->concurrency_mode != kConcurrencyModeTimer && ts->concurrency_mode != kConcurrencyModeCounter)
    {
        LOGF("MuxClient: Invalid concurrency mode: %u", ts->concurrency_mode);
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->concurrency_mode == kConcurrencyModeTimer)
    {
        int duration = 0;
        if (! getIntFromJsonObject(&duration, settings, "connection-duration"))
        {
            LOGF("MuxClient: connection-duration is not specified", duration);
            tunnelDestroy(t);
            return NULL;
        }
        if (duration <= 0)
        {
            LOGF("MuxClient: duration must be greater than 0, got %d", duration);
            tunnelDestroy(t);
            return NULL;
        }
        if (duration <= 60)
        {
            LOGF("MuxClient: This value is in Milliseconds: you are probably wrong with value lower than 60 , value is"
                 " %d",
                 duration);
            tunnelDestroy(t);
            return NULL;
        }

        ts->concurrency_duration = duration;
    }

    if (ts->concurrency_mode == kConcurrencyModeCounter)
    {
        int counter = 0;
        if (! getIntFromJsonObject(&counter, settings, "connection-capacity"))
        {
            LOGF("MuxClient: \"connection-capacity\" is not specified", counter);
            tunnelDestroy(t);
            return NULL;
        }

        if (counter <= 0)
        {
            LOGF("MuxClient: \"connection-capacity\" must be greater than 0, got %d", counter);
            tunnelDestroy(t);
            return NULL;
        }
        ts->concurrency_capacity = counter;
    }

    return t;
}
