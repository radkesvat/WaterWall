#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *reverseserverTunnelCreate(node_t *node)
{

    int wc = getWorkersCount();

    tunnel_t *t = tunnelCreate(node,
                               sizeof(reverseserver_tstate_t) + (wc * sizeof(reverseserver_thread_box_t)),
                               sizeof(reverseserver_lstate_t));
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &reverseserverTunnelUpStreamInit;
    t->fnFinU     = &reverseserverTunnelUpStreamFinish;
    t->fnPayloadU = &reverseserverTunnelUpStreamPayload;
    t->fnPauseU   = &reverseserverTunnelUpStreamPause;
    t->fnResumeU  = &reverseserverTunnelUpStreamResume;

    t->fnInitD    = &reverseserverTunnelDownStreamInit;
    t->fnEstD     = &reverseserverTunnelDownStreamEst;
    t->fnFinD     = &reverseserverTunnelDownStreamFinish;
    t->fnPayloadD = &reverseserverTunnelDownStreamPayload;
    t->fnPauseD   = &reverseserverTunnelDownStreamPause;
    t->fnResumeD  = &reverseserverTunnelDownStreamResume;

    t->onDestroy = &reverseserverTunnelDestroy;

    const cJSON *settings = node->node_settings_json;
    if (settings != NULL && ! cJSON_IsObject(settings))
    {
        LOGF("JSON Error: ReverseServer->settings (object field) : expected an object");
        tunnelDestroy(t);
        return NULL;
    }

    reverseserver_tstate_t *ts = tunnelGetState(t);
    int64_t                 activation_min = kReverseActivationDefaultMinSize;
    int64_t                 activation_max = kReverseActivationDefaultMaxSize;
    if (jsonGetObjectIntegerInRange(settings,
                                    "activation-min-size",
                                    kReverseActivationHeaderSize,
                                    kReverseActivationMaxSize,
                                    &activation_min) == kJsonValueInvalid ||
        jsonGetObjectIntegerInRange(settings,
                                    "activation-max-size",
                                    kReverseActivationHeaderSize,
                                    kReverseActivationMaxSize,
                                    &activation_max) == kJsonValueInvalid ||
        activation_min > activation_max)
    {
        LOGF("ReverseServer: activation sizes must be integers in [4, 65536] with min <= max");
        tunnelDestroy(t);
        return NULL;
    }
    ts->activation_min_size = (uint32_t) activation_min;
    ts->activation_max_size = (uint32_t) activation_max;
    for (int i = 0; i < wc; ++i)
    {
        atomic_init(&ts->threadlocal_pool[i].u_count, 0);
        atomic_init(&ts->threadlocal_pool[i].d_count, 0);
    }
    if (! reverseclientHandshakeBuildFromSettings(
            settings, "ReverseServer", &ts->handshake_bytes, &ts->handshake_length))
    {
        tunnelDestroy(t);
        return NULL;
    }

    tunnel_t *pipe_tunnel = pipetunnelCreate(t);
    if (! pipe_tunnel)
    {
        // The wrapper never took ownership, so the child is still this call's.
        reverseclientHandshakeDestroy(ts->handshake_bytes);
        tunnelDestroy(t);
        return NULL;
    }

    return pipe_tunnel;
}
