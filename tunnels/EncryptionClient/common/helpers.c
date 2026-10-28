#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelstateDestroy(encryptionclient_tstate_t *ts)
{
    memoryZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

void encryptionclientCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(! lineIsAlive(l)))
    {
        LOGF("EncryptionClient: attempted to close an already-destroyed line");
        abortProgramNow(1);
    }

    encryptionclient_lstate_t *ls = lineGetState(l, t);
    encryptionclientLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
