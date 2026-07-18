#include "structure.h"

void realityclientLinestateInitialize(realityclient_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (realityclient_lstate_t) {
        .read_stream    = bufferstreamCreate(pool, kRealityClientMaxFramePrefixSize),
        .handoff_stream = bufferstreamCreate(pool, 0),
        .pending_up     = bufferqueueCreate(2),
        .phase          = kRealityClientPhaseTlsHandshake,
    };
}

void realityclientLinestateDestroy(realityclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    bufferstreamDestroy(&ls->handoff_stream);
    bufferqueueDestroy(&ls->pending_up);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
