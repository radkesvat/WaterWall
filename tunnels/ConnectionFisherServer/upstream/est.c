#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("ConnectionFisherServer: upstream est disabled");
    abortProgramNow(1);
}
