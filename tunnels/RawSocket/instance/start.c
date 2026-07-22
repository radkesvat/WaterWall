#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketOnStart(tunnel_t *t)
{
    rawsocket_tstate_t *state = tunnelGetState(t);

    if (nodeIsLastInChain(t->node))
    {
        state->WriteReceivedPacket = t->prev->fnPayloadD;
        state->write_tunnel = t->prev;
    }
    else
    {
        state->WriteReceivedPacket = t->next->fnPayloadU;
        state->write_tunnel = t->next;
    }

    state->capture_device = caputredeviceCreate(state->capture_device_name, state->capture_ranges,
                                                state->capture_range_count, t, rawsocketOnIPPacketReceived);

    if (state->capture_device == NULL)
    {
        LOGF("CaptureDevice: could not create device");
        terminateProgram(1);
    }

    // we are not going to read, so pass read call back as null therfore no buffers for read will be allocated
    state->raw_device = rawdeviceCreate(state->raw_device_name, state->firewall_mark, t);

    if (! caputredeviceBringUp(state->capture_device))
    {
        LOGF("CaptureDevice: could not bring device up");
        terminateProgram(1);
    }
    rawdeviceBringUp(state->raw_device);
}
