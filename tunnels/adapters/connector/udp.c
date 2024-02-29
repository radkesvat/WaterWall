#include "shared.h"



static void on_udp_recv(hio_t *io, void *buf, int readbytes)
{
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    reserve(payload, readbytes);
    memcpy(rawBuf(payload), buf, readbytes);
    setLen(payload, readbytes);

    tunnel_t *self = (cstate)->tunnel;
    line_t *line = (cstate)->line;

    struct sockaddr *destaddr = hio_peeraddr(io);

    enum socket_address_type atype;

    if (destaddr->sa_family == AF_INET6)
        atype = SAT_IPV6;
    else
        atype = SAT_IPV4;

    if (!cstate->established)
    {
        cstate->established = true;
        context_t *est_context = newContext(line);
        est_context->est = true;
        est_context->src_io = io;
        est_context->dest_ctx.addr.sa = *destaddr;
        est_context->dest_ctx.atype = atype;
        self->packetDownStream(self, est_context);
        if (hevent_userdata(io) == NULL)
            return;
    }

    context_t *context = newContext(line);
    context->src_io = io;
    context->dest_ctx.atype = atype;
    context->payload = payload;
    context->dest_ctx.addr.sa = *destaddr;

    self->packetDownStream(self, context);
}

void connectorPacketUpStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        int bytes = bufLen(c->payload);

        if (c->dest_ctx.atype == SAT_DOMAINNAME)
        {
            if (!c->dest_ctx.resolved)
            {
                if (!connectorResolvedomain(&(c->dest_ctx)))
                {
                    free(CSTATE(c));
                    CSTATE_MUT(c) = NULL;
                    DISCARD_CONTEXT(c);
                    goto fail;
                }
            }
        }
        if (hio_is_closed(cstate->io))
        {
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            DISCARD_CONTEXT(c);
            goto fail;
        }
        hio_set_peeraddr(cstate->io, &(c->dest_ctx.addr.sa), sockaddr_len(&(c->dest_ctx.addr)));
        size_t nwrite = hio_write(cstate->io, rawBuf(c->payload), bytes);
        if (nwrite >= 0 && nwrite < bytes)
        {
            assert(false); // should not happen
        }

        DISCARD_CONTEXT(c);
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            assert(c->src_io != NULL);
            CSTATE_MUT(c) = malloc(sizeof(connector_con_state_t));
            memset(CSTATE(c), 0, sizeof(connector_con_state_t));
            connector_con_state_t *cstate = CSTATE(c);

            cstate->buffer_pool = buffer_pools[c->line->tid];
            cstate->tunnel = self;
            cstate->line = c->line;
            cstate->write_paused = false;
            cstate->queue = NULL;
            cstate->io_back = c->src_io;

            socket_context_t *dest = &(c->dest_ctx);
            // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);
            assert(dest->protocol == IPPROTO_UDP);
            hloop_t *loop = hevent_loop(c->src_io);

            int sockfd = socket(dest->addr.sa.sa_family, SOCK_DGRAM, 0);
            if (sockfd < 0)
            {
                LOGE("Connector: socket fd < 0");
                free(CSTATE(c));
                CSTATE_MUT(c) = NULL;
                goto fail;
            }

#ifdef OS_UNIX
            so_reuseaddr(sockfd, 1);
#endif
            sockaddr_u addr;

            sockaddr_set_ipport(&addr, "0.0.0.0", 0);

            if (bind(sockfd, &addr.sa, sockaddr_len(&addr)) < 0)
            {
                LOGE("UDP bind failed;");
                closesocket(sockfd);
                goto fail;
            }

            hio_t *upstream_io = hio_get(loop, sockfd);
            assert(upstream_io != NULL);

            cstate->io = upstream_io;
            hevent_set_userdata(upstream_io, cstate);
            hio_setcb_read(upstream_io, on_udp_recv);
            hio_read(upstream_io);
            destroyContext(c);
        }
        else if (c->fin)
        {
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            destroyLine(c->line);
            destroyContext(c);
            hio_close(io);
        }
    }
    return;
fail:
    context_t *fail_context = newContext(c->line);
    fail_context->fin = true;
    fail_context->src_io = c->src_io;
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
}

void connectorPacketDownStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        hio_t *io = CSTATE(c)->io;
        hevent_set_userdata(io, NULL);
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);
}
