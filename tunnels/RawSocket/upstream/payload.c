#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) l;
    // discard t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    // printIPPacketInfo("RawSocket sending: ", sbufGetRawPtr(buf));

    if (! writeToRawDevce(state->raw_device, buf))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }

}
