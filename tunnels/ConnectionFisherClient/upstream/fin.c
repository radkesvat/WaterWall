#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleMain)
    {
        connectionfisherclientCloseMainLineFromUpstream(t, l);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        connectionfisherclientCloseChildLine(t, l, false);
        return;
    }

    tunnelNextUpStreamFinish(t, l);
}
