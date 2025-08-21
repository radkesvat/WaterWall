#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverLinestateInitialize(obfuscatorserver_lstate_t *ls)
{
    discard ls;
}

void obfuscatorserverLinestateDestroy(obfuscatorserver_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(obfuscatorserver_lstate_t));
}
