#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *obfuscatorclientTunnelCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(obfuscatorclient_tstate_t), 0);

    t->fnInitD    = &obfuscatorclientTunnelDownStreamInit;
    t->fnPayloadU = &obfuscatorclientTunnelUpStreamPayload;
    t->fnPayloadD = &obfuscatorclientTunnelDownStreamPayload;

    t->onPrepare = &obfuscatorclientTunnelOnPrepair;
    t->onStart   = &obfuscatorclientTunnelOnStart;
    t->onStop    = &obfuscatorclientTunnelOnStop;
    t->onDestroy = &obfuscatorclientTunnelDestroy;

    obfuscatorclient_tstate_t *ts = tunnelGetState(t);

    const cJSON    *settings = node->node_settings_json;
    dynamic_value_t skip     = parseDynamicNumericValueFromJsonObject(settings, "skip", 3, "none", "ipv4", "transport");

    ts->method = parseDynamicNumericValueFromJsonObject(settings, "method", 1, "xor").status;
    ts->skip   = (skip.status == kDvsEmpty) ? kObfuscatorSkipNone : skip.status;

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

    if (ts->skip != kObfuscatorSkipNone && ts->skip != kObfuscatorSkipIpv4 && ts->skip != kObfuscatorSkipTransport)
    {
        LOGF("ObfuscatorClient: 'skip' must be one of 'none', 'ipv4', or 'transport'");
        tunnelDestroy(t);
        dynamicvalueDestroy(skip);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->tls_record_header, settings, "tls_record_header", false);
    if (getBoolFromJsonObject(&ts->tls_record_header, settings, "tls_header"))
    {
        LOGW("ObfuscatorClient: 'tls_header' is deprecated, use 'tls_record_header'");
    }

    dynamicvalueDestroy(skip);
    return t;
}
