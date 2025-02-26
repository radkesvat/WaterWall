#include "structure.h"

#include "loggers/network_logger.h"

static void localPacketReceived(worker_t *worker, void *arg1, void *arg2, void *arg3)
{
    (void) worker;
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

    assert(p->next == NULL);

    sbuf_t *buf;

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
    {
        sbufWrite(buf, p->payload, p->len);
    }

    static wid_t distributed_wid = 0;
    if (distributed_wid < getWorkersCount() - 1)
    {
        distributed_wid++;
    }
    else
    {
        distributed_wid = 0;
    }
    tunnel_t *t = (tunnel_t *) netif->state;

    sendWorkerMessage(distributed_wid, localPacketReceived, t, buf, NULL);

    return ERR_OK;
}

