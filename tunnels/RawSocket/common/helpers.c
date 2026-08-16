#include "structure.h"

#include "ipv4_packet_view.h"
#include "loggers/network_logger.h"

#include "loggers/log_rate_limiter.h"

enum
{
    kRawSocketChecksumLogIntervalMs = 5U * 1000U
};

/* Shared by every worker that writes to the raw device, so the gate is atomic. */
static atomic_log_rate_limiter_t rawsocket_checksum_failure_log;
static atomic_log_rate_limiter_t rawsocket_invalid_packet_log;

static bool rawsocketPacketIsExactIpv4(const sbuf_t *buf)
{
    ipv4_packet_view_t packet = {0};
    const uint32_t     length = sbufGetLength(buf);

    return ipv4packetviewParse(sbufGetRawPtr(buf), length, &packet) && packet.ip_total_length == length;
}

void rawsocketExitHook(void *userdata, int sig)
{
    discard sig;
    char   *cmdbuf = userdata;
    execCmd(cmdbuf);
}

void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    // packet is correctly filtered based on src/dest ip since we told net filter system
    tunnel_t *t = userdata;

    if (UNLIKELY(! atomicLoadRelaxed(&cdev->up)))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    /* Validate before any logging, typed header access, or packet dispatch. */
    if (UNLIKELY(! rawsocketPacketIsExactIpv4(buf)))
    {
        if (atomicLogRateLimiterShouldLog(&rawsocket_invalid_packet_log, kRawSocketChecksumLogIntervalMs))
        {
            LOGW("RawSocket: dropping malformed or unsupported captured packet");
        }
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    line_t *l = tunnelchainGetWorkerPacketLine(t->chain, wid);

    packettunnelLifecycleAnchorPublish(t, l, buf);
}

void rawsocketWriteStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard l;
    // discard t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    // printIPPacketInfo("RawSocket sending", sbufGetRawPtr(buf));
    /*
     * A refused recalculation means the packet is not a shape this can checksum
     * at all - a truncated header, a length that disagrees with the buffer -
     * so it is dropped rather than sent with whatever checksum bytes it happened
     * to hold. The request is consumed either way: the worker packet line is
     * persistent, and leaving it set made the next, unrelated packet on that
     * line ask for a recalculation nobody requested.
     */
    if (UNLIKELY(! packettunnelConsumeChecksumRequest(l, buf)))
    {
        if (atomicLogRateLimiterShouldLog(&rawsocket_checksum_failure_log, kRawSocketChecksumLogIntervalMs))
        {
            LOGW("RawSocket: dropping malformed, unsupported, or unchecksummable output");
        }
        lineReuseBuffer(l, buf);
        return;
    }

    if (! rawdeviceWrite(state->raw_device, buf))
    {
        lineReuseBuffer(l, buf);
    }
}
