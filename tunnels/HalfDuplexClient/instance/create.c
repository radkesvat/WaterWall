#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *halfduplexclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, kTunnelStateSize, kLineStateSize);
    if (! t)
    {
        return NULL;
    }

    t->fnInitU    = &halfduplexclientTunnelUpStreamInit;
    t->fnEstU     = &halfduplexclientTunnelUpStreamEst;
    t->fnFinU     = &halfduplexclientTunnelUpStreamFinish;
    t->fnPayloadU = &halfduplexclientTunnelUpStreamPayload;
    t->fnPauseU   = &halfduplexclientTunnelUpStreamPause;
    t->fnResumeU  = &halfduplexclientTunnelUpStreamResume;

    t->fnInitD    = &halfduplexclientTunnelDownStreamInit;
    t->fnEstD     = &halfduplexclientTunnelDownStreamEst;
    t->fnFinD     = &halfduplexclientTunnelDownStreamFinish;
    t->fnPayloadD = &halfduplexclientTunnelDownStreamPayload;
    t->fnPauseD   = &halfduplexclientTunnelDownStreamPause;
    t->fnResumeD  = &halfduplexclientTunnelDownStreamResume;

    return t;
}
