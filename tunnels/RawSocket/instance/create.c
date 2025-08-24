#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *rawsocketCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(rawsocket_tstate_t), sizeof(rawsocket_lstate_t));

    t->fnInitU    = &rawsocketUpStreamInit;
    t->fnEstU     = &rawsocketUpStreamEst;
    t->fnFinU     = &rawsocketUpStreamFinish;
    t->fnPayloadU = &rawsocketUpStreamPayload;
    t->fnPauseU   = &rawsocketUpStreamPause;
    t->fnResumeU  = &rawsocketUpStreamResume;

    t->fnInitD    = &rawsocketDownStreamInit;
    t->fnEstD     = &rawsocketDownStreamEst;
    t->fnFinD     = &rawsocketDownStreamFinish;
    t->fnPayloadD = &rawsocketDownStreamPayload;
    t->fnPauseD   = &rawsocketDownStreamPause;
    t->fnResumeD  = &rawsocketDownStreamResume;

    t->onPrepare = &rawsocketOnPrepair;
    t->onStart   = &rawsocketOnStart;
    t->onDestroy = &rawsocketDestroy;

    rawsocket_tstate_t *state    = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;

    // not forced
    getStringFromJsonObjectOrDefault(&(state->capture_device_name), settings, "capture-device-name",
                                     "unnamed-capture-device");
    getStringFromJsonObjectOrDefault(&(state->raw_device_name), settings, "raw-device-name", "unnamed-raw-device");

    dynamic_value_t fmode =
        parseDynamicNumericValueFromJsonObject(settings, "capture-filter-mode", 2, "source-ip", "dest-ip");
    if (fmode.status < kDvsSourceIp)
    {
        LOGF("JSON Error: RawSocket->settings->capture-filter-mode (string field) : mode is not specified or invalid");
        rawsocketDestroy(t);
        return NULL;
    }

    state->capture_ip = NULL;
    if (! getStringFromJsonObject(&state->capture_ip, settings, "capture-ip"))
    {
        LOGF("JSON Error: RawSocket->settings->capture-ip (string field) : mode is not specified or invalid");
    }

    if (fmode.status == kDvsSourceIp)
    {
        ;
    }
    else
    {
        LOGF("RawSocket cannot yet capture outgoing, use tun device for that");
        return NULL;
    }

    getIntFromJsonObjectOrDefault((&state->firewall_mark), settings, "mark", 0);
    state->write_direction_upstream = (node->hash_next != 0x0);

    return t;
}
