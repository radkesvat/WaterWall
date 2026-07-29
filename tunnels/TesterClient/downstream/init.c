#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterClient: downStreamInit disabled");
    abortProgramNow(1);
}
