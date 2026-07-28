#include "structure.h"

#include "loggers/network_logger.h"

void socks5clientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Socks5Client: UpStreamEst is disabled");
    abortProgramNow(1);
}
