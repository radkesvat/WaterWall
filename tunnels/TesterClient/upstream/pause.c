#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: upStreamPause disabled");
    abortProgramNow(1);
}
