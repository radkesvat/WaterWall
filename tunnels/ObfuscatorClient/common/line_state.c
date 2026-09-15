#include "structure.h"

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls, line_t *l)
{
    *ls = (obfuscatorclient_lstate_t) {.read_stream = bufferstreamCreate(lineGetBufferPool(l), 0)};
}
void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
