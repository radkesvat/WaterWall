#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) l;
    rawsocket_tstate_t *state = tunnelGetState(t);

    if (! writeToRawDevce(state->raw_device, buf))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
