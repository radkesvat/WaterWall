#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    rawsocket_tstate_t *state = tunnelGetState(t);
    if (state->capture_device != NULL && ! capturedeviceRequestStop(state->capture_device))
    {
        LOGW("RawSocket: capture device stop request failed");
    }
    if (state->raw_device != NULL)
    {
        rawdeviceRequestStop(state->raw_device);
    }
}

void rawsocketOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    rawsocket_tstate_t *state = tunnelGetState(t);
    if (state->capture_device)
    {
        if (! caputredeviceBringDown(state->capture_device))
        {
            LOGW("RawSocket: capture device bring down completed with cleanup errors");
        }
    }
    if (state->raw_device && ! rawdeviceBringDown(state->raw_device))
    {
        LOGW("RawSocket: raw device bring down completed with cleanup errors");
    }
}
