#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: upStreamEst disabled");
    abortProgramNow(1);
}
