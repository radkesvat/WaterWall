#include "structure.h"

void realityserverLinestateInitialize(realityserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (realityserver_lstate_t) {
        .read_stream = bufferstreamCreate(pool, kRealityServerFramePrefixSize),
        .mode        = kRealityServerModePending,
    };
}

void realityserverLinestateDestroy(realityserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
