#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kTunDeviceChecksumLogIntervalMs = 5U * 1000U
};

/* Shared by every packet worker writing this device. */
static atomic_log_rate_limiter_t tundevice_checksum_failure_log;
static atomic_log_rate_limiter_t tundevice_invalid_packet_log;

static bool tundevicePacketIsExactIpv4(const sbuf_t *buf)
{
    ipv4_packet_view_t packet = {0};
    const uint32_t     length = sbufGetLength(buf);

    return ipv4packetviewParse(sbufGetRawPtr(buf), length, &packet) && packet.ip_total_length == length;
}

static void logPacket(sbuf_t *buf)
{
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

    printIPPacketInfo("TunDevice recv", sbufGetRawPtr(buf), sbufGetLength(buf));

afterlog:;

#endif
}

void tundeviceOnIPPacketReceived(tun_device_t *tdev, void *userdata, sbuf_t *buf, wid_t wid)
{

    tunnel_t *t = userdata;

    if (UNLIKELY(! tundeviceIsUp(tdev)))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    /* Validate before logging or any typed header access. */
    if (UNLIKELY(! tundevicePacketIsExactIpv4(buf)))
    {
        if (atomicLogRateLimiterShouldLog(&tundevice_invalid_packet_log, kTunDeviceChecksumLogIntervalMs))
        {
            LOGW("TunDevice: dropping malformed or unsupported IP input");
        }
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    logPacket(buf);

    line_t *l = tunnelchainGetWorkerPacketLine(t->chain, wid);
    packettunnelLifecycleAnchorPublish(t, l, buf);
}

void tundeviceTunnelWritePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tundevice_tstate_t *state = tunnelGetState(t);
    tun_device_t       *tdev  = state->tdev;

    if (UNLIKELY(! packettunnelConsumeChecksumRequest(buf)))
    {
        if (atomicLogRateLimiterShouldLog(&tundevice_checksum_failure_log, kTunDeviceChecksumLogIntervalMs))
        {
            LOGW("TunDevice: dropping malformed, unsupported, or unchecksummable output");
        }
        lineReuseBuffer(l, buf);
        return;
    }

#if LOG_PACKET_INFO
    printIPPacketInfo("TunDevice write", sbufGetRawPtr(buf), sbufGetLength(buf));
#endif

    if (UNLIKELY(! tundeviceIsUp(tdev)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (! tundeviceWrite(tdev, buf))
    {
        lineReuseBuffer(l, buf);
    }
}
