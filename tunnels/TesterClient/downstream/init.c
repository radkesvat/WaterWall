#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    testerclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->packet_mode)
    {
        LOGF("TesterClient: downStreamInit disabled");
        abortProgramNow(1);
    }

    testerclient_lstate_t *ls = lineGetState(l, t);
    if (ls->read_stream.pool == NULL)
    {
        testerclientLinestateInitialize(ls, lineGetBufferPool(l));
    }
}
