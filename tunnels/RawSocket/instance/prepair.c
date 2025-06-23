#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketOnPrepair(tunnel_t *t)
{
    (void)t;
    rawsocket_tstate_t *state    = tunnelGetState(t);

    bringCaptureDeviceUP(state->capture_device);
    bringRawDeviceUP(state->raw_device);

}

