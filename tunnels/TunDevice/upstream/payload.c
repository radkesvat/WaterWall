#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t       *tdev  = state->tdev;

    // Clear the existing checksum field before calculation
    // IPH_CHKSUM_SET(ip_header, 0);

    // // Calculate and set the checksum
    // IPH_CHKSUM_SET(ip_header, inet_chksum(ip_header, IP_HLEN));

#if LOG_PACKET_INFO
    struct ip_hdr *ip_header = (struct ip_hdr *) sbufGetMutablePtr(buf);
    printIPPacketInfo("TunDevice write", (const unsigned char *) ip_header);
#endif

    if (! tundeviceWrite(tdev, buf))
    {
        LOGW("TunDevice: Write failed! worker %d ", lineGetWID(l));
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
