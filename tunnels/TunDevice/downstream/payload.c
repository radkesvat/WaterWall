#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t       *tdev  = state->tdev;

    struct ip_hdr *ip_header = (struct ip_hdr *) sbufGetMutablePtr(buf);

    // // Clear the existing checksum field before calculation
    // IPH_CHKSUM_SET(ip_header, 0);

    // // Calculate and set the checksum
    // IPH_CHKSUM_SET(ip_header, inet_chksum(ip_header, IP_HLEN));

    printIPPacketInfo("TunDevice write", (const unsigned char*)ip_header);

    if (! tundeviceWrite(tdev, buf))
    {
        LOGW("TunDevice: Write failed");
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
