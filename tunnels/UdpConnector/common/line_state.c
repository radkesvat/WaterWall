#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorLinestateInitialize(udpconnector_lstate_t *ls, tunnel_t *t, line_t *l, wio_t *io)
{

    *ls = (udpconnector_lstate_t){
        .tunnel = t,
        .line   = l,
        .io     = io,
        .established = false,
        .read_paused = false,
    };

    weventSetUserData(io, ls);

}

void udpconnectorLinestateDestroy(udpconnector_lstate_t *ls)
{
    memoryZeroAligned32(ls, sizeof(udpconnector_lstate_t));
}
