#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls, buffer_pool_t *pool, bool splice_output)
{
    spliceframereaderInit(&ls->reader, pool, kHeaderSize, kMaxReentryBytes, kReadChargeLimit, splice_output);
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    spliceframereaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpovertcpclient_lstate_t)));
}
