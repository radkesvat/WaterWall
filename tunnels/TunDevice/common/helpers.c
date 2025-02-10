#include "structure.h"

#include "loggers/network_logger.h"


void tundeviceOnIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    (void) tdev;
    tunnel_t           *t  = userdata;

#if LOG_PACKET_INFO
    printIPPacketInfo("TunDevice recv",sbufGetRawPtr(buf));
#endif


    line_t *l = tunnelchainGetPacketLine(t->chain,wid);
    lineLock(l);
    tunnelNextUpStreamPayload(t, l, buf);

    if (! lineIsAlive(l))
    {
        LOGF("TunDevice: line is not alive, rule of packet tunnels is violated");
        exit(1);
    }
    lineUnlock(l);
}
