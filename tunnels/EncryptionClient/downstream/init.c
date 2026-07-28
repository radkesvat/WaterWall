#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("EncryptionClient: DownStreamInit is disabled");

    abortProgramNow(1);
}
