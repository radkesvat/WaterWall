#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientLinestateInitialize(encryptionclient_lstate_t *ls, buffer_pool_t *pool, bool datagram)
{
    ls->datagram = datagram;
    if (! datagram)
        ls->read_stream = bufferstreamCreate(pool, kEncryptionFramePrefixSize);
}

void encryptionclientLinestateDestroy(encryptionclient_lstate_t *ls)
{
    if (! ls->datagram)
        bufferstreamDestroy(&ls->read_stream);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(encryptionclient_lstate_t)));
}
