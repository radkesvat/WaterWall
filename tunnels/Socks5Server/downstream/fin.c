#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindUdpRemote)
    {
        socks5serverDetachRemoteFromClient(ls);
        socks5serverLinestateDestroy(ls);
        lineDestroy(l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        // next/upstream side finished us. The unified close sends a SOCKS5 failure reply (only if
        // the request was still pending), closes prev, and safely handles the re-entrant write.
        socks5serverCloseControlLineFromDownstream(t, l);
        return;
    }

    socks5serverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
