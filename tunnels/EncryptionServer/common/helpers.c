#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelstateDestroy(encryptionserver_tstate_t *ts)
{
    memoryZero(ts->key, sizeof(ts->key));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

void encryptionserverCloseLineBidirectional(tunnel_t *t, line_t *l)
{
    if (UNLIKELY(! lineIsAlive(l)))
    {
        LOGF("EncryptionServer: attempted to close an already-destroyed line");
        abortProgramNow(1);
    }

    encryptionserver_lstate_t *ls = lineGetState(l, t);
    encryptionserverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
    tunnelPrevDownStreamFinish(t, l);
}
