#include "structure.h"

#include "loggers/network_logger.h"

void rawsocketExitHook(void *userdata, int sig)
{
    (void) sig;
    char *cmdbuf = userdata;
    execCmd(cmdbuf);
}

void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    // packet is correctly filtered based on src/dest ip since we told net filter system
    (void) cdev;
    tunnel_t *t = userdata;

    // printIPPacketInfo("RawSocket received", sbufGetRawPtr(buf));
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        // LOGW("RawSocket: Received packet with unsupported IP version %d", IPH_V(ipheader));
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
        return;
    }

    line_t *l = tunnelchainGetPacketLine(t->chain, wid);

    rawsocket_tstate_t *state = tunnelGetState(t);
    
    state->WriteReceivedPacket(state->write_tunnel, l, buf);
}

void rawsocketWriteStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) l;
    // discard t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    // printIPPacketInfo("RawSocket sending", sbufGetRawPtr(buf));
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
            calcFullPacketChecksum(sbufGetMutablePtr(buf));
        }
        l->recalculate_checksum                  = false;
        l->do_not_recalculate_transport_checksum = false;
    }

    if (UNLIKELY(state->raw_device->up == false))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
        LOGW("RawSocket: device is down, cannot write packet");
        return;
    }

    if (! rawdeviceWrite(state->raw_device, buf))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
