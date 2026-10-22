#include "structure.h"

tunnel_t *quicclientTunnelCreate(node_t *node)
{
    const cJSON         *json = node->node_settings_json;
    quic_node_settings_t settings;
    if (! quicReadCommonSettings(node, &settings))
    {
        return NULL;
    }

    settings.engine.is_client = true;
    if (! quicReadString(json, "sni", &settings.engine.sni, true) ||
        ! quicReadString(json, "ca-file", &settings.engine.ca_file, false) ||
        ! quicReadBoolean(json, "verify", &settings.engine.verify))
    {
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, sizeof(quicclient_tstate_t), sizeof(quicclient_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }
    if (! quicConfigureTunnel(t, &settings, &quicclientOutput))
    {
        tunnelDestroy(t);
        return NULL;
    }

    t->fnInitU          = quicclientTunnelUpStreamInit;
    t->fnPayloadU       = quicclientTunnelUpStreamPayload;
    t->fnPayloadD       = quicclientTunnelDownStreamPayload;
    t->fnFinU           = quicclientTunnelUpStreamFinish;
    t->fnFinD           = quicclientTunnelDownStreamFinish;
    t->fnEstD           = quicclientTunnelDownStreamEst;
    t->fnPauseU         = quicclientTunnelUpStreamPause;
    t->fnPauseD         = quicclientTunnelDownStreamPause;
    t->fnResumeU        = quicclientTunnelUpStreamResume;
    t->fnResumeD        = quicclientTunnelDownStreamResume;
    t->onQuiesceRequest = quicclientTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = quicclientTunnelOnWorkerQuiesce;
    t->onDestroy        = quicclientTunnelDestroy;
    return t;
}
