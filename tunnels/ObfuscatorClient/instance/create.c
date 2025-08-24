#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *obfuscatorclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(obfuscatorclient_tstate_t), sizeof(obfuscatorclient_lstate_t));

    t->fnInitU    = &obfuscatorclientTunnelUpStreamInit;
    t->fnEstU     = &obfuscatorclientTunnelUpStreamEst;
    t->fnFinU     = &obfuscatorclientTunnelUpStreamFinish;
    t->fnPayloadU = &obfuscatorclientTunnelUpStreamPayload;
    t->fnPauseU   = &obfuscatorclientTunnelUpStreamPause;
    t->fnResumeU  = &obfuscatorclientTunnelUpStreamResume;

    t->fnInitD    = &obfuscatorclientTunnelDownStreamInit;
    t->fnEstD     = &obfuscatorclientTunnelDownStreamEst;
    t->fnFinD     = &obfuscatorclientTunnelDownStreamFinish;
    t->fnPayloadD = &obfuscatorclientTunnelDownStreamPayload;
    t->fnPauseD   = &obfuscatorclientTunnelDownStreamPause;
    t->fnResumeD  = &obfuscatorclientTunnelDownStreamResume;

    t->onPrepare = &obfuscatorclientTunnelOnPrepair;
    t->onStart   = &obfuscatorclientTunnelOnStart;
    t->onDestroy = &obfuscatorclientTunnelDestroy;

    obfuscatorclient_tstate_t *ts = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    ts->method = parseDynamicNumericValueFromJsonObject(settings, "method", 1, "xor").status;

    if (ts->method == kObfuscatorMethodXor)
    {
        int i_xor_key = 0;
        if (! getIntFromJsonObject(&i_xor_key, settings, "xor_key"))
        {
            LOGF("ObfuscatorClient: 'xor_key' not set");
            tunnelDestroy(t);
            return NULL;
        }

        ts->xor_key = (uint8_t) i_xor_key;
    }
    else
    {
        LOGF("ObfuscatorClient: 'method' not set or unsupported");
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
