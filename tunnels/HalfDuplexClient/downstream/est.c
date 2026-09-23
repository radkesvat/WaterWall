#include "structure.h"

void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    halfduplexclient_lstate_t *child = lineGetState(l, t);
    line_t                    *main  = child->main_line;
    if (main == NULL)
        return;
    halfduplexclient_lstate_t *ls = lineGetState(main, t);
    ls->est_seen                  = true;
    discard halfduplexclientNotifyEstablished(t, main);
}
