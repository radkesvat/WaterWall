#include "structure.h"

#include "loggers/network_logger.h"

static void printIPPacketInfo(const char *devname, const unsigned char *buffer)
{
    char  logbuf[256];
    int   rem = sizeof(logbuf);
    char *ptr = logbuf;
    int   ret;

    uint8_t version = buffer[0] >> 4;

    if (version == 4)
    {
        struct ip_hdr *ip_header = (struct ip_hdr *)buffer;
        ip4_addr_t src_addr, dst_addr;
        memcpy(&src_addr, &ip_header->src, sizeof(ip4_addr_t));
        memcpy(&dst_addr, &ip_header->dest, sizeof(ip4_addr_t));
        const char *src_ip = ip4addr_ntoa(&src_addr);
        const char *dst_ip = ip4addr_ntoa(&dst_addr);
        ret = snprintf(ptr, rem, "TunDevice: %s => From %s to %s, Data: ", devname, src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)buffer;
        ip6_addr_t src_addr, dst_addr;
        memcpy(&src_addr, &ip6_header->src, sizeof(ip6_addr_t));
        memcpy(&dst_addr, &ip6_header->dest, sizeof(ip6_addr_t));
        const char *src_ip = ip6addr_ntoa(&src_addr);
        const char *dst_ip = ip6addr_ntoa(&dst_addr);
        ret = snprintf(ptr, rem, "TunDevice: %s => From %s to %s, Data: ", devname, src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "TunDevice: %s => Unknown IP version, Data: ", devname);
    }

    ptr += ret;
    rem -= ret;

    for (int i = 0; i < 16; i++)
    {
        ret = snprintf(ptr, rem, "%02x ", buffer[i]);
        ptr += ret;
        rem -= ret;
    }
    *ptr = '\0';

    LOGD(logbuf);
}

void tundeviceOnIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    (void) tdev;
    tunnel_t           *t  = userdata;

#if LOG_PACKET_INFO
    printIPPacketInfo("TunDevice",sbufGetRawPtr(buf));
#endif

    // bufferpoolResuesBuffer(getWorkerBufferPool(tid), buf);

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
