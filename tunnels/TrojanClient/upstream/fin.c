#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    trojanclientCloseLine(t, l, kTrojanClientCloseFromPrev);
}

void trojanclientDomainSetupTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    trojanclient_domain_setup_lstate_t *ls = lineGetState(l, t);

    trojanclientDomainSetupLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

void trojanclientDomainSetupTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    trojanclient_domain_setup_lstate_t *ls = lineGetState(l, t);

    trojanclientDomainSetupLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
