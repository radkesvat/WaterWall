#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);

    ls->prev_paused = true;

    if (ls->kind == kSocks5ClientLineKindUdpApp)
    {
        line_t *udp_l = ls->udp_line;
        if (udp_l != NULL && lineIsAlive(udp_l))
        {
            discard lineCallWithRef(udp_l, tunnelNextUpStreamPause, t);
        }
        return;
    }

    // Application receive pressure must not stop the SOCKS handshake itself.
    if (ls->phase == kSocks5ClientPhaseEstablished && ls->read_pause_sent != true)
    {
        ls->read_pause_sent = true;
        tunnelNextUpStreamPause(t, l);
    }
}
