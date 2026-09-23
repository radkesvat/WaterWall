#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    ls->prev_paused = false;

    if (ls->kind == kSocks5ClientLineKindUdpApplication)
    {
        line_t *udp_l = ls->udp_line;
        if (udp_l != NULL && lineIsAlive(udp_l))
        {
            discard lineCallWithRef(udp_l, tunnelNextUpStreamResume, t);
        }
        return;
    }

    // Application receive pressure must not stop the SOCKS handshake itself.
    if (ls->phase == kSocks5ClientPhaseEstablished && ls->read_pause_sent != false)
    {
        ls->read_pause_sent = false;
        tunnelNextUpStreamResume(t, l);
    }
}
