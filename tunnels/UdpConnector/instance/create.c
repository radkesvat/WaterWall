#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpconnectorTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(udpconnector_tstate_t), sizeof(udpconnector_lstate_t));

    t->fnInitU    = &udpconnectorTunnelUpStreamInit;
    t->fnEstU     = &udpconnectorTunnelUpStreamEst;
    t->fnFinU     = &udpconnectorTunnelUpStreamFinish;
    t->fnPayloadU = &udpconnectorTunnelUpStreamPayload;
    t->fnPauseU   = &udpconnectorTunnelUpStreamPause;
    t->fnResumeU  = &udpconnectorTunnelUpStreamResume;

    t->fnInitD    = &udpconnectorTunnelDownStreamInit;
    t->fnEstD     = &udpconnectorTunnelDownStreamEst;
    t->fnFinD     = &udpconnectorTunnelDownStreamFinish;
    t->fnPayloadD = &udpconnectorTunnelDownStreamPayload;
    t->fnPauseD   = &udpconnectorTunnelDownStreamPause;
    t->fnResumeD  = &udpconnectorTunnelDownStreamResume;

    t->onPrepair = &udpconnectorTunnelOnPrepair;
    t->onStart   = &udpconnectorTunnelOnStart;
    t->onDestroy = &udpconnectorTunnelDestroy;

    const cJSON *settings = node->node_settings_json;

    udpconnector_tstate_t *state = tunnelGetState(t);

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: UdpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    getBoolFromJsonObject(&(state->reuse_addr), settings, "reuseaddr");

    state->dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (state->dest_addr_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->address (string field) : The vaule was empty or invalid");
        return NULL;
    }
    if (state->dest_addr_selected.status == kDvsConstant)
    {
        if (addressIsIp(state->dest_addr_selected.string))
        {
            addresscontextSetIpAddress(&state->constant_dest_addr, state->dest_addr_selected.string);
        }
        else
        {
            addresscontextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.string,
                                            stringLength(state->dest_addr_selected.string));
        }
    }

    state->dest_port_selected =
        parseDynamicNumericValueFromJsonObject(settings, "port", 2, "src_context->port", "dest_context->port");

    if (state->dest_port_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->port (number field) : The vaule was empty or invalid");
        return NULL;
    }
    if (state->dest_port_selected.status == kDvsConstant)
    {
        addresscontextSetPort(&(state->constant_dest_addr), state->dest_port_selected.integer);
    }

    return t;
}
