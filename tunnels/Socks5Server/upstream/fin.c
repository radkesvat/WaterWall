#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    socks5server_lstate_t *ls = lineGetState(l, t);

    switch (ls->kind)
    {
    case kSocks5ServerLineKindControlTcp:
        lineLock(l);
        if (ls->prev_finished)
        {
            ls->next_finished = true;
            lineUnlock(l);
            return;
        }
        // This is a real upstream Finish, so suppress the helper's downstream-close leg.
        ls->prev_finished = true;
        lineUnlock(l);
        socks5serverCloseControlLineBidirectional(t, l);
        return;

    case kSocks5ServerLineKindUdpClient:
        lineLock(l);
        // This is a real upstream Finish, so suppress the helper's downstream-close leg.
        ls->prev_finished = true;
        lineUnlock(l);
        socks5serverCloseUdpClientLine(t, l);
        return;

    case kSocks5ServerLineKindUdpRemote:
        socks5serverCloseUdpRemoteLine(t, l);
        return;

    case kSocks5ServerLineKindNone:
    default:
        socks5serverLinestateDestroy(ls);
        tunnelNextUpStreamFinish(t, l);
        return;
    }
}
