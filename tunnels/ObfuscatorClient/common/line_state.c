#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls)
{
    discard ls;
}

void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(obfuscatorclient_lstate_t));
}
