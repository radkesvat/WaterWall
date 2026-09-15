#include "structure.h"

void obfuscatorserverLinestateInitialize(obfuscatorserver_lstate_t *ls, line_t *l)
{
    *ls = (obfuscatorserver_lstate_t) {.read_stream = bufferstreamCreate(lineGetBufferPool(l), 0)};
}
void obfuscatorserverLinestateDestroy(obfuscatorserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
