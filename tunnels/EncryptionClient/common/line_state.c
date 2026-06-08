#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientLinestateInitialize(encryptionclient_lstate_t *ls, buffer_pool_t *pool)
{

    ls->read_stream = bufferstreamCreate(pool, kEncryptionFramePrefixSize);
}

void encryptionclientLinestateDestroy(encryptionclient_lstate_t *ls)
{

    bufferstreamDestroy(&ls->read_stream);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(encryptionclient_lstate_t)));
}
