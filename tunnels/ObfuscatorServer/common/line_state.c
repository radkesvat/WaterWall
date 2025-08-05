#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverLinestateInitialize(obfuscatorserver_lstate_t *ls)
{
    discard ls;
}

void obfuscatorserverLinestateDestroy(obfuscatorserver_lstate_t *ls)
{
    memorySet(ls, 0, sizeof(obfuscatorserver_lstate_t));
}
