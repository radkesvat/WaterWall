#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: upStreamInit disabled");
    abortProgramNow(1);
}
