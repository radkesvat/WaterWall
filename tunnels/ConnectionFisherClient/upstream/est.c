#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("ConnectionFisherClient: upstream est disabled");
    terminateProgram(1);
}
