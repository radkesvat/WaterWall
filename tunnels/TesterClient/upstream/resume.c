#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: upStreamResume disabled");
    abortProgramNow(1);
}
