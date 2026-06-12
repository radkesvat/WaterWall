#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("AuthenticationClient: UpStreamPayload is disabled");
    terminateProgram(1);
}
