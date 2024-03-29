#include "types.h"
#include "utils/sockutils.h"
#include "loggers/network_logger.h"

static void cleanup(connector_con_state_t *cstate)
{
    if (cstate->current_w)
    {
        if (cstate->current_w->payload)
        {
            DISCARD_CONTEXT(cstate->current_w);
        }
        destroyContext(cstate->current_w);
    }
    destroyContextQueue(cstate->queue);
    free(cstate);
}

static bool resume_write_queue(connector_con_state_t *cstate)
{
    context_queue_t *queue = (cstate)->queue;
    context_t **cw = &((cstate)->current_w);
    hio_t *io = cstate->io;
    hio_t *last_resumed_io = NULL;
    while (contextQueueLen(queue) > 0)
    {
        *cw = contextQueuePop(queue);
        hio_t *upstream_io = (*cw)->src_io;

        if ((*cw)->payload == NULL)
        {
            destroyContext((*cw));
            *cw = NULL;

            if (upstream_io && last_resumed_io != upstream_io)
            {
                last_resumed_io = upstream_io;
                hio_read(upstream_io);
            }
            continue;
        }

        int bytes = bufLen((*cw)->payload);
        int nwrite = hio_write(io, rawBuf((*cw)->payload), bytes);
        if (nwrite >= 0 && nwrite < bytes)
        {
            return false; // write pending
        }
        else
        {
            reuseBuffer(cstate->buffer_pool, (*cw)->payload);
            (*cw)->payload = NULL;
            contextQueuePush(queue, (*cw));
            *cw = NULL;
        }
    }
    return true;
}

static void on_write_complete(hio_t *io, const void *buf, int writebytes)
{
    // resume the read on other end of the connection
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));
    if (cstate == NULL)
        return;

    context_t **cw = &((cstate)->current_w);
    context_queue_t *queue = (cstate)->queue;

    hio_t *upstream_io = (*cw)->src_io;
    if (hio_write_is_complete(io))
    {

        reuseBuffer(cstate->buffer_pool, (*cw)->payload);
        (*cw)->payload = NULL;
        context_t *cpy_ctx = (*cw);
        *cw = NULL;

        if (contextQueueLen(queue) > 0)
        {
            contextQueuePush(cstate->queue, cpy_ctx);
            resume_write_queue(cstate);
        }
        else
        {
            destroyContext(cpy_ctx);
            cstate->write_paused = false;
            hio_setcb_write(io, NULL);

            if (upstream_io)
                hio_read(upstream_io);
        }
    }
}

static void on_recv(hio_t *io, void *buf, int readbytes)
{
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));
    if (cstate == NULL)
        return;

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    setLen(payload, readbytes);
    memcpy(rawBuf(payload), buf, readbytes);

    tunnel_t *self = (cstate)->tunnel;
    line_t *line = (cstate)->line;

    context_t *context = newContext(line);
    context->src_io = io;
    context->payload = payload;

    self->downStream(self, context);
}

static void on_close(hio_t *io)
{
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));
    if (cstate != NULL)
        LOGD("Connector: received close for FD:%x ",
             (int)hio_fd(io));
    else
        LOGD("Connector: sent close for FD:%x ",
             (int)hio_fd(io));

    if (cstate != NULL)
    {
        tunnel_t *self = (cstate)->tunnel;
        line_t *line = (cstate)->line;
        context_t *context = newFinContext(line);
        context->src_io = io;
        self->downStream(self, context);
    }
}

static void onOutBoundConnected(hio_t *upstream_io)
{

    connector_con_state_t *cstate = hevent_userdata(upstream_io);
#ifdef PROFILE
    struct timeval tv2;
    gettimeofday(&tv2, NULL);

    double time_spent = (double)(tv2.tv_usec - (cstate->__profile_conenct).tv_usec) / 1000000 + (double)(tv2.tv_sec - (cstate->__profile_conenct).tv_sec);
    LOGD("Connector: tcp connect took %d ms", (int)(time_spent * 1000));
#endif

    tunnel_t *self = cstate->tunnel;
    line_t *line = cstate->line;
    hio_setcb_read(upstream_io, on_recv);

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};

    LOGD("Connector: connection succeed FD:%x [%s] => [%s]",
         (int)hio_fd(upstream_io),
         SOCKADDR_STR(hio_localaddr(upstream_io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(upstream_io), peeraddrstr));

    context_t *est_context = newContext(line);
    est_context->est = true;
    est_context->src_io = upstream_io;
    self->downStream(self, est_context);
}

void connectorUpStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->write_paused)
        {
            if (c->src_io)
                hio_read_stop(c->src_io);
            contextQueuePush(cstate->queue, c);
        }
        else
        {
            cstate->current_w = c;

            int bytes = bufLen(c->payload);
            int nwrite = hio_write(cstate->io, rawBuf(c->payload), bytes);
            if (nwrite >= 0 && nwrite < bytes)
            {
                cstate->write_paused = true;
                if (c->src_io)
                    hio_read_stop(c->src_io);
                hio_setcb_write(cstate->io, on_write_complete);
            }
            else
            {
                reuseBuffer(cstate->buffer_pool, cstate->current_w->payload);
                cstate->current_w->payload = NULL;
                cstate->current_w = NULL;
                destroyContext(c);
            }
        }
    }
    else
    {
        if (c->init)
        {

            CSTATE_MUT(c) = malloc(sizeof(connector_con_state_t));
            memset(CSTATE(c), 0, sizeof(connector_con_state_t));
            connector_con_state_t *cstate = CSTATE(c);
#ifdef PROFILE
            gettimeofday(&(cstate->__profile_conenct), NULL);
#endif

            cstate->buffer_pool = buffer_pools[c->line->tid];
            cstate->tunnel = self;
            cstate->line = c->line;
            cstate->queue = newContextQueue(cstate->buffer_pool);
            cstate->write_paused = true;

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

            // sockaddr_set_ipport(&(final_ctx.addr), "127.0.0.1", 443);

            LOGW("Connector: initiating tcp connection");
            if (final_ctx.atype == SAT_DOMAINNAME)
            {
                if (!final_ctx.resolved)
                {
                    if (!connectorResolvedomain(&final_ctx))
                    {
                        free(final_ctx.domain);
                        destroyContextQueue(cstate->queue);
                        free(CSTATE(c));
                        CSTATE_MUT(c) = NULL;
                        goto fail;
                    }
                }
                free(final_ctx.domain);
            }

            hloop_t *loop = loops[c->line->tid];
            int sockfd = socket(final_ctx.addr.sa.sa_family, SOCK_STREAM, 0);
            if (sockfd < 0)
            {
                LOGE("Connector: socket fd < 0");
                destroyContextQueue(cstate->queue);
                free(CSTATE(c));
                CSTATE_MUT(c) = NULL;
                goto fail;
            }
            if (STATE(self)->tcp_no_delay)
            {
                tcp_nodelay(sockfd, 1);
            }
            if (STATE(self)->reuse_addr)
            {
                so_reuseport(sockfd, 1);
            }

            if (STATE(self)->tcp_fast_open)
            {
                const int yes = 1;
                setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &yes, sizeof(yes));
            }

            hio_t *upstream_io = hio_get(loop, sockfd);
            assert(upstream_io != NULL);

            hio_set_peeraddr(upstream_io, &(final_ctx.addr.sa), sockaddr_len(&(final_ctx.addr)));
            cstate->io = upstream_io;
            hevent_set_userdata(upstream_io, cstate);

            // io <=> upstream_io
            // hio_setup_upstream(io, upstream_io);
            hio_setcb_connect(upstream_io, onOutBoundConnected);
            hio_setcb_close(upstream_io, on_close);

            // printf("connect to ");
            // SOCKADDR_PRINT(hio_peeraddr(upstream_io));
            hio_connect(upstream_io);
            destroyContext(c);
        }
        else if (c->fin)
        {
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            cleanup(cstate);
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
void connectorDownStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
#ifdef PROFILE
        struct timeval tv1, tv2;
        gettimeofday(&tv1, NULL);
        {
            self->dw->downStream(self->dw, c);
        }
        gettimeofday(&tv2, NULL);
        double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 + (double)(tv2.tv_sec - tv1.tv_sec);
        LOGD("Connector: tcp downstream took %d ms", (int)(time_spent * 1000));
#else
        self->dw->downStream(self->dw, c);

#endif
    }
    else
    {

        if (c->est)
        {
            cstate->established = true;
            hio_read(cstate->io);
            if (resume_write_queue(cstate))
                cstate->write_paused = false;
            else
                hio_setcb_write(cstate->io, on_write_complete);

            self->dw->downStream(self->dw, c);
        }
        else if (c->fin)
        {
            hio_t *io = CSTATE(c)->io;
            hevent_set_userdata(io, NULL);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
            self->dw->downStream(self->dw, c);
        }
    }
}