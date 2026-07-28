#include "structure.h"

#include "loggers/network_logger.h"

void softiplimiterTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("SoftIpLimiter: downstream init disabled");
    abortProgramNow(1);
}
