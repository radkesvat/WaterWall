#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    // tlsclientPrintSSLState(ls->ssl);

    // Raw transport close is directional: free TLS resources without
    // SSL_shutdown(), so no close_notify response is generated.
    tlsclientLinestateDestroy(ls);
    tunnelPrevDownStreamFinish(t, l);
}
