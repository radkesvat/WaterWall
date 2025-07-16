#include "structure.h"

#include "loggers/network_logger.h"

static void logPacket(struct tun_device_s *tdev, tunnel_t t, sbuf_t *buf, wid_t wid)
{

    discard tdev;
    discard wid;
    discard t;
    discard buf;
    

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
#if ! LOG_V6
    else if (IPH_V(iphdr) == 6)
    {
        goto afterlog;
    }
#endif

    printIPPacketInfo("TunDevice recv", sbufGetRawPtr(buf));

afterlog:;

#endif
}

void tundeviceOnIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{

    tunnel_t *t = userdata;
    logPacket(tdev, *t, buf, wid);

    tundevice_tstate_t *state = tunnelGetState(t);

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        // LOGW("TunDevice: Received packet with unsupported IP version %d", IPH_V(ipheader));
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    if (UNLIKELY(tdev->up == false))
    {
        // this may happen at start of other side creates device and gets packets on multiple workers
        LOGW("TunDevice: device is down, cannot process packet");
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    line_t *l = tunnelchainGetPacketLine(t->chain, wid);
#ifdef DEBUG
    lineLock(l);
#endif


    state->WriteReceivedPacket(t, l, buf);
    
    tunnelNextUpStreamPayload(t, l, buf);

    
#ifdef DEBUG
    if (! lineIsAlive(l))
    {
        LOGF("TunDevice: line is not alive, rule of packet tunnels is violated");
        terminateProgram(1);
    }

    lineUnlock(l);
#endif
}


void tundeviceTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
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

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (l->recalculate_checksum && IPH_V(ipheader) == 4)
    {
        if (UNLIKELY(l->do_not_recalculate_transport_checksum == true))
        {
            IPH_CHKSUM_SET(ipheader, 0);
            IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
        }
        else
        {
            recalculatePacketChecksum(sbufGetMutablePtr(buf));
        }
        l->recalculate_checksum                  = false;
        l->do_not_recalculate_transport_checksum = false;
    }

    if (UNLIKELY(state->tdev->up == false))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
        LOGW("TunDevice: device is down, cannot write packet");
        return;
    }

    if (! tundeviceWrite(tdev, buf))
    {
        LOGW("TunDevice: Write failed! worker %d ", lineGetWID(l));
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
