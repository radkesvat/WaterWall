#include "structure.h"

#include "loggers/network_logger.h"

void tundeviceOnIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    discard tdev;
    tunnel_t *t = userdata;

#if LOG_PACKET_INFO
    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetRawPtr(buf);

    if (IPH_V(iphdr) == 4)
    {

        ip4_addr_t dstv4;
        ip4_addr_copy(dstv4, iphdr->dest);

#if ! LOG_SSDP
        ip4_addr_t ssdp_ipv4;
        IP4_ADDR(&ssdp_ipv4, 239, 255, 255, 250);
        if (ip4AddrEqual(&dstv4, &ssdp_ipv4))
        {
            goto afterlog;
        }
#endif
#if ! LOG_MDNS
        ip4_addr_t mdns_ipv4;
        IP4_ADDR(&mdns_ipv4, 224, 0, 0, 251);
        if (ip4AddrEqual(&dstv4, &mdns_ipv4))
        {
            goto afterlog;
        }
#endif
    }
#if !LOG_V6
    else if (IPH_V(iphdr) == 6)
    {
        goto afterlog;
    }
#endif

    printIPPacketInfo("TunDevice recv", sbufGetRawPtr(buf));

#endif

afterlog:;

    line_t *l = tunnelchainGetPacketLine(t->chain, wid);
    lineLock(l);
    tunnelNextUpStreamPayload(t, l, buf);

    if (! lineIsAlive(l))
    {
        LOGF("TunDevice: line is not alive, rule of packet tunnels is violated");
        exit(1);
    }
    lineUnlock(l);
}
