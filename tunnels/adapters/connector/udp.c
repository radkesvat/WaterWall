#include "types.h"
#include "utils/sockutils.h"
#include "loggers/network_logger.h"

static void on_recv(hio_t *io, void *buf, int readbytes)
{
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    setLen(payload, readbytes);
    writeRaw(payload,buf,readbytes);

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
        self->packetDownStream(self, est_context);
        if (hevent_userdata(io) == NULL)
            return;
    }

    context_t *context = newContext(line);
    context->src_io = io;
    context->payload = payload;

    self->packetDownStream(self, context);
}

void connectorPacketUpStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        int bytes = bufLen(c->payload);

        if (hio_is_closed(cstate->io))
        {
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            DISCARD_CONTEXT(c);
            goto fail;
        }

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
            CSTATE_MUT(c) = malloc(sizeof(connector_con_state_t));
            memset(CSTATE(c), 0, sizeof(connector_con_state_t));
            connector_con_state_t *cstate = CSTATE(c);

            cstate->buffer_pool = buffer_pools[c->line->tid];
            cstate->tunnel = self;
            cstate->line = c->line;
            cstate->write_paused = false;
            cstate->data_queue = NULL;
            cstate->finished_queue = NULL;

            // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);

            hloop_t *loop = loops[c->line->tid];

            sockaddr_u host_addr = {0};
            sockaddr_set_ipport(&host_addr, "0.0.0.0", 0);

            int sockfd = socket(host_addr.sa.sa_family, SOCK_DGRAM, 0);
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
            hio_setcb_read(upstream_io, on_recv);
            hio_read(upstream_io);

            socket_context_t final_ctx = {0};
            // fill the final_ctx address based on settings
            {
                socket_context_t *src_ctx = &(c->line->src_ctx);
                socket_context_t *dest_ctx = &(c->line->dest_ctx);
                connector_state_t *state = STATE(self);

                if (state->dest_addr.status == cdvs_from_source)
                    copySocketContextAddr(&final_ctx, &src_ctx);
                else if (state->dest_addr.status == cdvs_from_dest)
                    copySocketContextAddr(&final_ctx, &dest_ctx);
                else
                {
                    final_ctx.atype = state->dest_atype;
                    if (state->dest_atype == SAT_DOMAINNAME)
                    {
                        final_ctx.domain = malloc(state->dest_domain_len + 1);
                        memcpy(final_ctx.domain, state->dest_addr.value_ptr, state->dest_domain_len + 1);
                        final_ctx.resolved = false;
                        final_ctx.addr.sa.sa_family = AF_INET; // addr resolve will change this
                    }
                    else
                        sockaddr_set_ip(&(final_ctx.addr), state->dest_addr.value_ptr);
                }

                if (state->dest_port.status == cdvs_from_source)
                    sockaddr_set_port(&(final_ctx.addr), sockaddr_port(&(src_ctx->addr)));
                else if (state->dest_port.status == cdvs_from_dest)
                    sockaddr_set_port(&(final_ctx.addr), sockaddr_port(&(dest_ctx->addr)));
                else
                    sockaddr_set_port(&(final_ctx.addr), state->dest_port.value);
            }

            if (final_ctx.atype == SAT_DOMAINNAME)
            {
                if (!final_ctx.resolved)
                {
                    if (!connectorResolvedomain(&(final_ctx)))
                    {
                        free(final_ctx.domain);
                        free(CSTATE(c));
                        CSTATE_MUT(c) = NULL;
                        DISCARD_CONTEXT(c);
                        goto fail;
                    }
                }
                free(final_ctx.domain);
            }
            hio_set_peeraddr(cstate->io, &(final_ctx.addr.sa), sockaddr_len(&(final_ctx.addr)));

            destroyContext(c);
        }
        else if (c->fin)
        {
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            destroyContext(c);
            hio_close(io);
        }
    }
    return;
fail:;
    self->dw->downStream(self->dw, newFinContext(c->line));
    destroyContext(c);
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
