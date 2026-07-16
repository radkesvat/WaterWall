#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    tlsclient_lstate_t *ls = lineGetState(l, t);

    // Direct close policy: free TLS resources without SSL_shutdown(), so no
    // close_notify is generated toward the wire side.
    // We do this to mimic chrome, which does not send close_notify when the connection is closed by the user.
    tlsclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
