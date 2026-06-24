#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vlessclientCloseLine(t, l, kVlessClientCloseFromPrev);
}

void vlessclientDomainSetupTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vlessclient_domain_setup_lstate_t *ls = lineGetState(l, t);

    vlessclientDomainSetupLinestateDestroy(ls);
    tunnelNextUpStreamFinish(t, l);
}

void vlessclientDomainSetupTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vlessclient_domain_setup_lstate_t *ls = lineGetState(l, t);

    vlessclientDomainSetupLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
