#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("EncryptionServer: UpstreamEst is disabled");
    abortProgramNow(1);
}
