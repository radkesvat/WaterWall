#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(tcpconnector_tstate_t), sizeof(tcpconnector_lstate_t), true);

    t->fnInitU    = &tcpconnectorTunnelUpStreamInit;
    t->fnEstU     = &tcpconnectorTunnelUpStreamEst;
    t->fnFinU     = &tcpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &tcpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &tcpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &tcpconnectorTunnelUpStreamResume;

    t->fnInitD    = &tcpconnectorTunnelDownStreamInit;
    t->fnEstD     = &tcpconnectorTunnelDownStreamEst;
    t->fnFinD     = &tcpconnectorTunnelDownStreamFinish;
    t->fnPayloadD = &tcpconnectorTunnelDownStreamPayload;
    t->fnPauseD   = &tcpconnectorTunnelDownStreamPause;
    t->fnResumeD  = &tcpconnectorTunnelDownStreamResume;

    tcplistener_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

     if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TcpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }


      getBoolFromJsonObjectOrDefault(&(state->option_tcp_no_delay), settings, "nodelay", true);
    getBoolFromJsonObjectOrDefault(&(state->option_tcp_fast_open), settings, "fastopen", false);
    getBoolFromJsonObjectOrDefault(&(state->reuse_addr), settings, "reuseaddr", false);
    getIntFromJsonObjectOrDefault(&(state->domain_strategy), settings, "domain-strategy", 0);


    return t;
}
