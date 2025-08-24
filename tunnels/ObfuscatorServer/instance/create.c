#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *obfuscatorserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(obfuscatorserver_tstate_t), sizeof(obfuscatorserver_lstate_t));

    t->fnInitU    = &obfuscatorserverTunnelUpStreamInit;
    t->fnEstU     = &obfuscatorserverTunnelUpStreamEst;
    t->fnFinU     = &obfuscatorserverTunnelUpStreamFinish;
    t->fnPayloadU = &obfuscatorserverTunnelUpStreamPayload;
    t->fnPauseU   = &obfuscatorserverTunnelUpStreamPause;
    t->fnResumeU  = &obfuscatorserverTunnelUpStreamResume;

    t->fnInitD    = &obfuscatorserverTunnelDownStreamInit;
    t->fnEstD     = &obfuscatorserverTunnelDownStreamEst;
    t->fnFinD     = &obfuscatorserverTunnelDownStreamFinish;
    t->fnPayloadD = &obfuscatorserverTunnelDownStreamPayload;
    t->fnPauseD   = &obfuscatorserverTunnelDownStreamPause;
    t->fnResumeD  = &obfuscatorserverTunnelDownStreamResume;

    t->onPrepare = &obfuscatorserverTunnelOnPrepair;
    t->onStart   = &obfuscatorserverTunnelOnStart;
    t->onDestroy = &obfuscatorserverTunnelDestroy;

    obfuscatorserver_tstate_t *ts = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    ts->method = parseDynamicNumericValueFromJsonObject(settings, "method", 1, "xor").status;

    if (ts->method == kObfuscatorMethodXor)
    {
        int i_xor_key = 0;
        if (! getIntFromJsonObject(&i_xor_key, settings, "xor_key"))
        {
            LOGF("ObfuscatorServer: 'xor_key' not set");
            tunnelDestroy(t);
            return NULL;
        }

        ts->xor_key = (uint8_t) i_xor_key;
    }
    else
    {
        LOGF("ObfuscatorServer: 'method' not set or unsupported");
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
