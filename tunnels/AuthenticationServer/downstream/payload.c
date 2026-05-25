#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
    LOGF("AuthenticationServer: DownStreamPayload is disabled");
    terminateProgram(1);
}
