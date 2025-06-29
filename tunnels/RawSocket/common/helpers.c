#include "structure.h"

#include "loggers/network_logger.h"

static void something(void)
{
    // This function is not implemented yet
}

void rawsocketExitHook(void *userdata, int sig)
{
    (void) sig;
    char* cmdbuf = userdata;
    execCmd(cmdbuf);
}

void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    // packet is correctly filtered based on src/dest ip since we told net filter system
    (void) cdev;
    tunnel_t *t = userdata;

    //rawsocket_tstate_t *state = tunnelGetState(t);
    //printIPPacketInfo("RawSocket received: ", sbufGetRawPtr(buf));

    line_t *l = tunnelchainGetPacketLine(t->chain, wid);
    lineLock(l);
    tunnelPrevDownStreamPayload(t, l, buf);

    if (! lineIsAlive(l))
    {
        LOGF("RawSocket: line is not alive, rule of packet tunnels is violated");
        exit(1);
    }
    lineUnlock(l);
}

void rawsocketWriteStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    (void) l;
    // discard t;
    rawsocket_tstate_t *state = tunnelGetState(t);

    // printIPPacketInfo("RawSocket sending: ", sbufGetRawPtr(buf));
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (l->recalculate_checksum)
    {
        IPH_CHKSUM_SET(ipheader, 0);
        IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
        l->recalculate_checksum = false;
    }

    if (! rawdeviceWrite(state->raw_device, buf))
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(lineGetWID(l)), buf);
    }
}
