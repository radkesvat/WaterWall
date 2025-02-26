#include "structure.h"

#include "loggers/network_logger.h"

static void localThreadPacketReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    tunnel_t *t   = (tunnel_t *) arg1;
    sbuf_t   *buf = (sbuf_t *) arg2;
    (void) arg3;

    tunnelPrevDownStreamPayload(t, tunnelchainGetPacketLine(tunnelGetChain(t), worker->wid), buf);
}

void updateCheckSumTcp(u16_t *_hc, const void *_orig, const void *_new, int n)
{
    const u16_t *orig = _orig;
    const u16_t *new  = _new;
    u16_t hc          = ~*_hc;
    while (n--)
    {
        /* HC' = ~(~HC + ~m + m') */
        u32_t s;
        s = (u32_t) hc + ((~*orig) & 0xffff) + *new;
        while (s & 0xffff0000)
        {
            s = (s & 0xffff) + (s >> 16);
        }
        hc = (u16_t) s;
        orig++;
        new ++;
    }
    *_hc = ~hc;
}

void updateCheckSumUdp(u16_t *hc, const void *orig, const void *new, int n)
{
    if (! *hc)
    {
        return;
    }
    updateCheckSumTcp(hc, orig, new, n);
    if (! *hc)
    {
        *hc = 0xffff;
    }
}

err_t ptcNetifOutput(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    (void) netif;
    (void) ipaddr;
    (void) p;

    // i this i should not play with the lock, i have no idea about the state of the tcpip thread
    // LWIP_ASSERT_CORE_LOCKED(); // test code , is it necessary?
    // UNLOCK_TCPIP_CORE();

    tunnel_t *t   = netif->state;
    wid_t     wid = getWID();
    sbuf_t   *buf;

    if (p->len <= SMALL_BUFFER_SIZE)
    {
        buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    }
    else
    {
        buf = bufferpoolGetLargeBuffer(getWorkerBufferPool(getWID()));
    }

    sbufSetLength(buf, p->len);

    // if (p->tot_len - p->len >= 128)
    // {
    //     memoryCopy128(sbufGetMutablePtr(buf), p->payload, p->len);
    // }
    // else
    // {
    pbuf_copy_partial(p, sbufGetMutablePtr(buf), p->len, 0);
    // }

    // localThreadPacketReceived(getNextDistributionWID(), localPacketReceived, t, buf, NULL);
    tunnelPrevDownStreamPayload(t, tunnelchainGetPacketLine(tunnelGetChain(t), wid), buf);

    return ERR_OK;
}
