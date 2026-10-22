#include "structure.h"

void headerclientLinestateDestroy(headerclient_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
