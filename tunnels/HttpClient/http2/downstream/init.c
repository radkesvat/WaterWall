#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HttpClient(v2): DownStream Init is disabled");
    terminateProgram(1);
}
