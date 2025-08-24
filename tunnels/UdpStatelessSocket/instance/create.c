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
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-address (string field) : The data is valid ip address");
        return NULL;
    }

    int temp_port;
    if(! getIntFromJsonObject(&(temp_port), settings, "listen-port"))
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-port (number field) : The data was empty or invalid");
        return NULL;
    }
    if(temp_port < 0 || temp_port > 65535)
    {
        LOGF("JSON Error: UdpStatelessSocket->settings->listen-port (number field) : The data was not in the range of 0-65535");
        return NULL;
    }
    state->listen_port = (uint16_t)temp_port;



    state->io = wloopCreateUdpServer(getWorkerLoop(getWID()), state->listen_address,state->listen_port);

    if(!state->io)
    {
        LOGF("UdpStatelessSocket: could not create udp socket");
        return NULL;
    }

    state->io_wid = getWID();

    weventSetUserData(state->io, t);
    wioSetCallBackRead(state->io, udpstatelesssocketOnRecvFrom);
    wioRead(state->io);

    
    return t;
}
