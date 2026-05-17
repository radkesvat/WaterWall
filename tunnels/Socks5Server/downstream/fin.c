#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    socks5server_lstate_t *ls = lineGetState(l, t);

    if (ls->kind == kSocks5ServerLineKindUdpRemote)
    {
        lineLock(l);
        socks5serverDetachRemoteFromClient(ls);
        ls->next_finished = true;
        socks5serverLinestateDestroy(ls);
        lineDestroy(l);
        lineUnlock(l);
        return;
    }

    if (ls->kind == kSocks5ServerLineKindControlTcp)
    {
        lineLock(l);

        bool send_connect_failure = ls->phase == kSocks5ServerPhaseConnectWaitEst && ! ls->connect_reply_sent;
        socks5serverUnregisterUdpAssociation(ls);
        ls->next_finished = true;
        bool close_prev   = ! ls->prev_finished;
        ls->prev_finished = true;

        if (send_connect_failure)
        {
            sbuf_t *reply = socks5serverCreateCommandReply(l, 0x01, NULL);
            if (reply != NULL)
            {
                tunnelPrevDownStreamPayload(t, l, reply);
            }
        }

        socks5serverLinestateDestroy(ls);

        if (lineIsAlive(l) && close_prev)
        {
            tunnelPrevDownStreamFinish(t, l);
        }
        lineUnlock(l);
        return;
    }

    socks5serverLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
