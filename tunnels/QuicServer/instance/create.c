#include "structure.h"

tunnel_t *quicserverTunnelCreate(node_t *node)
{
    const cJSON         *json = node->node_settings_json;
    quic_node_settings_t settings;
    if (! quicReadCommonSettings(node, &settings))
    {
        return NULL;
    }

    settings.engine.is_client = false;
    if (! quicReadString(json, "cert-file", &settings.engine.cert_file, true) ||
        ! quicReadString(json, "key-file", &settings.engine.key_file, true))
    {
        return NULL;
    }

    tunnel_t *t = tunnelCreate(node, sizeof(quicserver_tstate_t), sizeof(quicserver_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }
    if (! quicConfigureTunnel(t, &settings, &quicserverOutput))
    {
        tunnelDestroy(t);
        return NULL;
    }

    t->fnInitU          = quicserverTunnelUpStreamInit;
    t->fnPayloadU       = quicserverTunnelUpStreamPayload;
    t->fnPayloadD       = quicserverTunnelDownStreamPayload;
    t->fnFinU           = quicserverTunnelUpStreamFinish;
    t->fnFinD           = quicserverTunnelDownStreamFinish;
    t->fnEstD           = quicserverTunnelDownStreamEst;
    t->fnPauseU         = quicserverTunnelUpStreamPause;
    t->fnPauseD         = quicserverTunnelDownStreamPause;
    t->fnResumeU        = quicserverTunnelUpStreamResume;
    t->fnResumeD        = quicserverTunnelDownStreamResume;
    t->onQuiesceRequest = quicserverTunnelOnQuiesceRequest;
    t->onWorkerQuiesce  = quicserverTunnelOnWorkerQuiesce;
    t->onDestroy        = quicserverTunnelDestroy;
    return t;
}
