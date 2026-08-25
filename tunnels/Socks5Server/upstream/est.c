#include "structure.h"

#include "loggers/network_logger.h"

void socks5serverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    socks5serverRequireCurrentLineWorker(l, "upstream Est");
    discard t;
    LOGF("Socks5Server: UpStreamEst is disabled");
    abortProgramNow(1);
}
