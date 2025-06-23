#include "structure.h"

#include "loggers/network_logger.h"

static const char *ip_tables_enable_queue_mi  = "iptables -I INPUT -s %s -j NFQUEUE --queue-num %d";
static const char *ip_tables_disable_queue_mi = "iptables -D INPUT -s %s -j NFQUEUE --queue-num %d";


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

    t->onPrepair = &rawsocketOnPrepair;
    t->onStart   = &rawsocketOnStart;
    t->onDestroy = &rawsocketDestroy;

    rawsocket_tstate_t *state    = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;
    state->queue_number          = 200 + (fastRand() % 200);

    // not forced
    getStringFromJsonObjectOrDefault(&(state->capture_device_name), settings, "capture-device-name",
                                     "unnamed-capture-device");
    getStringFromJsonObjectOrDefault(&(state->raw_device_name), settings, "raw-device-name", "unnamed-raw-device");

    dynamic_value_t fmode =
        parseDynamicNumericValueFromJsonObject(settings, "capture-filter-mode", 2, "source-ip", "dest-ip");
    if (fmode.status < kDvsSourceIp)
    {
        LOGF("JSON Error: RawSocket->settings->capture-filter-mode (string field) : mode is not specified or invalid");
        return NULL;
    }

    state->capture_ip = NULL;
    if (! getStringFromJsonObject(&state->capture_ip, settings, "capture-ip"))
    {
        LOGF("JSON Error: RawSocket->settings->capture-ip (string field) : mode is not specified or invalid");
    }

    char *cmdbuf = memoryAllocate(200);

    if (fmode.status == kDvsSourceIp)
    {
        stringNPrintf(cmdbuf, 100, ip_tables_enable_queue_mi, state->capture_ip, (int) state->queue_number);
        if (execCmd(cmdbuf).exit_code != 0)
        {
            LOGF("CaptureDevicer: command failed: %s", cmdbuf);
            return NULL;
        }

        state->onexit_command = cmdbuf;
        stringNPrintf(cmdbuf, 100, ip_tables_disable_queue_mi, state->capture_ip, (int) state->queue_number);
        
        
        
        registerAtExitCallBack(rawsocketExitHook, t);
    }
    else
    {
        LOGF("RawSocket cannot yet capture outgoing");
        return NULL;
    }

    
    state->capture_device = createCaptureDevice(state->capture_device_name, state->queue_number, t, rawsocketOnIPPacketReceived);

    if (state->capture_device == NULL)
    {
        LOGF("CaptureDevice: could not create device");
        return NULL;
    }

    uint32_t fwmark = 0;
    getIntFromJsonObjectOrDefault((int *) &fwmark, settings, "mark", 0);
    // we are not going to read, so pass read call back as null therfore no buffers for read will be allocated
    state->raw_device = createRawDevice(state->raw_device_name, fwmark, t, NULL);


    return t;
}
