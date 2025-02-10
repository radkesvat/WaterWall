#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t *tdev = state->tdev;
    if (! tundeviceWrite(tdev, buf))
    {
        LOGW("TunDevice: tundeviceWrite failed");
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }

}
