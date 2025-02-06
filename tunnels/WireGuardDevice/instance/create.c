#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *wireguarddeviceTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(wireguarddevice_tstate_t), sizeof(wireguarddevice_lstate_t));

    t->fnInitU    = &wireguarddeviceTunnelUpStreamInit;
    t->fnEstU     = &wireguarddeviceTunnelUpStreamEst;
    t->fnFinU     = &wireguarddeviceTunnelUpStreamFinish;
    t->fnPayloadU = &wireguarddeviceTunnelUpStreamPayload;
    t->fnPauseU   = &wireguarddeviceTunnelUpStreamPause;
    t->fnResumeU  = &wireguarddeviceTunnelUpStreamResume;

    t->fnInitD    = &wireguarddeviceTunnelDownStreamInit;
    t->fnEstD     = &wireguarddeviceTunnelDownStreamEst;
    t->fnFinD     = &wireguarddeviceTunnelDownStreamFinish;
    t->fnPayloadD = &wireguarddeviceTunnelDownStreamPayload;
    t->fnPauseD   = &wireguarddeviceTunnelDownStreamPause;
    t->fnResumeD  = &wireguarddeviceTunnelDownStreamResume;

    return t;
}
