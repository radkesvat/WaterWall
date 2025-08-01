#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    // tlsclientPrintSSLState(ls->ssl);

    tlsclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
