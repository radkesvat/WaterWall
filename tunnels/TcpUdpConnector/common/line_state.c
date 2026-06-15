#include "structure.h"

void tcpudpconnectorLinestateInitialize(tcpudpconnector_lstate_t *ls, tunnel_t *selected_connector)
{
    ls->selected_connector = selected_connector;
}

void tcpudpconnectorLinestateDestroy(tcpudpconnector_lstate_t *ls)
{
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tcpudpconnector_lstate_t)));
}
