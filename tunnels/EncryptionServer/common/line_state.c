#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverLinestateInitialize(encryptionserver_lstate_t *ls, buffer_pool_t *pool, bool datagram)
{
    ls->datagram = datagram;
    if (! datagram)
        ls->read_stream = bufferstreamCreate(pool, kEncryptionFramePrefixSize);
}

void encryptionserverLinestateDestroy(encryptionserver_lstate_t *ls)
{
    if (! ls->datagram)
        bufferstreamDestroy(&ls->read_stream);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(encryptionserver_lstate_t)));
}
