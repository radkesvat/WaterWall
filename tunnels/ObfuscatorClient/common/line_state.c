#include "structure.h"

void obfuscatorclientLinestateInitialize(obfuscatorclient_lstate_t *ls, line_t *l, bool from_downstream)
{
    *ls = (obfuscatorclient_lstate_t) {.read_stream                 = bufferstreamCreate(lineGetBufferPool(l), 0),
                                       .initialized_from_downstream = from_downstream};
}
void obfuscatorclientLinestateDestroy(obfuscatorclient_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
