#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    connectionfisherclient_lstate_t *ls = lineGetState(l, t);

    if (ls->role == kConnectionFisherClientRoleChild)
    {
        connectionfisherclientCloseChildLineFromDownstream(t, l, false);
        return;
    }

    if (ls->role == kConnectionFisherClientRoleMain)
    {
        connectionfisherclientCloseMainLine(t, l);
        return;
    }

    tunnelPrevDownStreamFinish(t, l);
}
