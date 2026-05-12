#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *udpstatelesssocketTunnelCreate(node_t *node)
{
    tunnel_t *t = adapterCreate(node, sizeof(udpstatelesssocket_tstate_t), sizeof(udpstatelesssocket_lstate_t), true);

    t->fnInitU    = &udpstatelesssocketTunnelUpStreamInit;
    t->fnEstU     = &udpstatelesssocketTunnelUpStreamEst;
    t->fnFinU     = &udpstatelesssocketTunnelUpStreamFinish;
    t->fnPayloadU = &udpstatelesssocketTunnelUpStreamPayload;
    t->fnPauseU   = &udpstatelesssocketTunnelUpStreamPause;
    t->fnResumeU  = &udpstatelesssocketTunnelUpStreamResume;

    t->fnInitD    = &udpstatelesssocketTunnelDownStreamInit;
    t->fnEstD     = &udpstatelesssocketTunnelDownStreamEst;
    t->fnFinD     = &udpstatelesssocketTunnelDownStreamFinish;
    t->fnPayloadD = &udpstatelesssocketTunnelDownStreamPayload;
    t->fnPauseD   = &udpstatelesssocketTunnelDownStreamPause;
    t->fnResumeD  = &udpstatelesssocketTunnelDownStreamResume;

    t->onPrepare = &udpstatelesssocketTunnelOnPrepair;
    t->onStart   = &udpstatelesssocketTunnelOnStart;
    t->onDestroy = &udpstatelesssocketTunnelDestroy;

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->listen_address), settings, "listen-address"))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-address (string field) : The data was empty or invalid");
        return NULL;
    }
    if (! addressIsIp(state->listen_address))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-address (string field) : The data is not a valid ip address");
        return NULL;
    }

    char *source_ip = NULL;
    if (getStringFromJsonObject(&source_ip, settings, "source-ip"))
    {
        if (! addressIsIp(source_ip))
        {
            LOGF("JSON Error: UdpStatelessSocket->settings->source-ip (string field) : The value must be a valid IP address");
            memoryFree(source_ip);
            return NULL;
        }
        memoryFree(state->listen_address);
        state->listen_address = source_ip;
        state->source_ip_configured = true;
    }

    getStringFromJsonObject(&(state->interface_name), settings, "interface");
    getIntFromJsonObjectOrDefault(&(state->fwmark), settings, "fwmark", -1);

    int temp_port;
    if (! getIntFromJsonObject(&(temp_port), settings, "listen-port"))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-port (number field) : The data was empty or invalid");
        return NULL;
    }
    if (temp_port < 0 || temp_port > 65535)
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-port (number field) : The data was not in the range of "
             "0-65535");
        return NULL;
    }
    state->listen_port = (uint16_t) temp_port;

    return t;
}
