#include "loggers/network_logger.h"
#include "types.h"
#include "utils/sockutils.h"

static void cleanup(connector_con_state_t *cstate)
{
    connector_state_t *state = STATE(cstate->tunnel);
    if (state->dest_addr.status == cdvs_constant)
    {

    }else if (state->dest_addr.status > cdvs_constant){
        free(cstate->line->dest_ctx)
    }

    free(cstate);
}
static void onUdpRecv(hio_t *io, void *buf, int readbytes)
{
    connector_con_state_t *cstate = (connector_con_state_t *) (hevent_userdata(io));

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    setLen(payload, readbytes);
    writeRaw(payload, buf, readbytes);

    tunnel_t *self = (cstate)->tunnel;
    line_t   *line = (cstate)->line;

    struct sockaddr *destaddr = hio_peeraddr(io);

    enum socket_address_type atype;

    if (destaddr->sa_family == AF_INET6)
    {
        atype = kSatIpV6;
    }
    else
    {
        atype = kSatIpV4;
    }

    if (! cstate->established)
    {
        cstate->established    = true;
        context_t *est_context = newContext(line);
        est_context->est       = true;
        est_context->src_io    = io;
        self->packetDownStream(self, est_context);
        if (hevent_userdata(io) == NULL)
        {
            return;
        }
    }

    context_t *context = newContext(line);
    context->src_io    = io;
    context->payload   = payload;

    self->packetDownStream(self, context);
}

void connectorPacketUpStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        unsigned int bytes = bufLen(c->payload);

        if (hio_is_closed(cstate->io))
        {
            cleanup(CSTATE(c));
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

            cstate->buffer_pool    = buffer_pools[c->line->tid];
            cstate->tunnel         = self;
            cstate->line           = c->line;
            cstate->write_paused   = false;
            cstate->data_queue     = NULL;
            cstate->finished_queue = NULL;

            // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);

            hloop_t *loop = loops[c->line->tid];

            sockaddr_u host_addr = {0};
            sockaddr_set_ipport(&host_addr, "0.0.0.0", 0);

            int sockfd = socket(host_addr.sa.sa_family, SOCK_DGRAM, 0);
            if (sockfd < 0)
            {
                LOGE("Connector: socket fd < 0");
                cleanup(CSTATE(c));
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
            hio_setcb_read(upstream_io, onUdpRecv);
            hio_read(upstream_io);

            socket_context_t* resolved_dest_context;
            // fill the resolved_dest_context address based on settings
            {
                socket_context_t  *src_ctx  = &(c->line->src_ctx);
                socket_context_t  *dest_ctx = &(c->line->dest_ctx);
                connector_state_t *state    = STATE(self);

                if (state->dest_addr.status == cdvs_from_source)
                {
                    resolved_dest_context = src_ctx;
                    // copySocketContextAddr(&resolved_dest_context, &src_ctx);
                }
                else if (state->dest_addr.status == cdvs_from_dest)
                {
                    resolved_dest_context = dest_ctx;
                    // copySocketContextAddr(&resolved_dest_context, &dest_ctx);
                }
                else
                {
                    resolved_dest_context.atype = state->dest_atype;
                    if (state->dest_atype == kSatDomainName)
                    {
                        resolved_dest_context.domain     = state->dest_addr.value_ptr;
                        resolved_dest_context.domain_len = state->dest_domain_len;
                        resolved_dest_context.resolved   = false;
                    }
                    else
                        sockaddr_set_ip(&(resolved_dest_context.addr), state->dest_addr.value_ptr);
                }

                if (state->dest_port.status == cdvs_from_source)
                    sockaddr_set_port(&(resolved_dest_context.addr), sockaddr_port(&(src_ctx->addr)));
                else if (state->dest_port.status == cdvs_from_dest)
                    sockaddr_set_port(&(resolved_dest_context.addr), sockaddr_port(&(dest_ctx->addr)));
                else
                    sockaddr_set_port(&(resolved_dest_context.addr), state->dest_port.value);
            }

            if (resolved_dest_context.atype == kSatDomainName)
            {
                if (! resolved_dest_context.resolved)
                {
                    if (! connectorResolvedomain(&(resolved_dest_context)))
                    {
                        free(resolved_dest_context.domain);
                        cleanup(CSTATE(c));
                        CSTATE_MUT(c) = NULL;
                        DISCARD_CONTEXT(c);
                        goto fail;
                    }
                }
                free(resolved_dest_context.domain);
            }
            hio_set_peeraddr(cstate->io, &(resolved_dest_context.addr.sa), sockaddr_len(&(resolved_dest_context.addr)));

            destroyContext(c);
        }
        else if (c->fin)
        {
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            cleanup(CSTATE(c));
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
        cleanup(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);
}
