#include "structure.h"

#include "loggers/network_logger.h"

static void something(void)
{
    // This function is not implemented yet
}

void rawsocketExitHook(void *userdata, int sig)
{
    (void) sig;
    rawsocket_tstate_t *state = tunnelGetState(userdata);
    execCmd(state->onexit_command);
}

void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    // packet is correctly filtered based on src/dest ip since we told net filter system
    (void) cdev;
    tunnel_t           *t  = userdata;
    // rawsocket_tstate_t *state = tunnelGetState(t);

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
