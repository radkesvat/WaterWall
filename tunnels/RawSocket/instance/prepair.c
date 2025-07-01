#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketOnPrepair(tunnel_t *t)
{
    (void) t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    state->capture_device =
        caputredeviceCreate(state->capture_device_name, state->capture_ip, t, rawsocketOnIPPacketReceived);

    if (state->capture_device == NULL)
    {
        LOGF("CaptureDevice: could not create device");
        terminateProgram(1);
    }

    // we are not going to read, so pass read call back as null therfore no buffers for read will be allocated
    state->raw_device = rawdeviceCreate(state->raw_device_name, state->firewall_mark, t, NULL);

    caputredeviceBringUp(state->capture_device);
    rawdeviceBringUp(state->raw_device);
}
