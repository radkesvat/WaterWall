#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("EncryptionClient: UpstreamEst is disabled");
    abortProgramNow(1);
}
