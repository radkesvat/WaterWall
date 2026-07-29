#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: upStreamFinish disabled");
    abortProgramNow(1);
}
