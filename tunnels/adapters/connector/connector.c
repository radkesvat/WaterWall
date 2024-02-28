#include "connector.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"

#define STATE(x) ((connector_state_t *)((x)->state))
#define CSTATE(x) ((connector_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

// enable profile to see how much it takes to connect and downstream write
// #define PROFILE 1

typedef struct connector_state_s
{
    // settings
    bool no_delay;

} connector_state_t;

typedef struct connector_con_state_s
{
#ifdef PROFILE
    struct timeval __profile_conenct;
#endif

    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;
    hio_t *io_back;

    buffer_pool_t *buffer_pool;
    context_queue_t *queue;
    context_t *current_w;

    bool write_paused;
    bool established;
} connector_con_state_t;

#undef hlog
#define hlog getDnsLogger()
static bool resolve_domain(socket_context_t *dest)
{
    uint16_t old_port = sockaddr_port(&(dest->addr));
    struct timeval tv1, tv2;
    gettimeofday(&tv1, NULL);
    /* resolve domain */
    {
        if (sockaddr_set_ipport(&(dest->addr), dest->domain, old_port) != 0)
        {
            LOGE("Connector: resolve failed  %s", dest->domain);
            return false;
        }
        else
        {
            char ip[60];
            sockaddr_str(&(dest->addr), ip, 60);
            LOGI("Connector: %s resolved to %s", dest->domain, ip);
        }
    }
    gettimeofday(&tv2, NULL);

    double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 + (double)(tv2.tv_sec - tv1.tv_sec);
    LOGD("Connector: dns resolve took %lf sec", time_spent);
    dest->resolved = true;
    return true;
}
#undef hlog
#define hlog getNetworkLogger()

static bool resume_write_queue(connector_con_state_t *cstate)
{
    context_queue_t *queue = (cstate)->queue;
    context_t **cw = &((cstate)->current_w);
    hio_t *io = cstate->io;
    while (contextQueueLen(queue) > 0)
    {
        *cw = contextQueuePop(queue);
        hio_t *upstream_io = (*cw)->src_io;

        if ((*cw)->payload == NULL)
        {
            destroyContext((*cw));

            if (upstream_io)
                hio_read(upstream_io);
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

        if (resume_write_queue(cstate))
        {
            destroyContext(cpy_ctx);
            cstate->write_paused = false;
            hio_setcb_write(io, NULL);

            if (upstream_io)
                hio_read(upstream_io);
        }
        else
        {
            contextQueuePush(cstate->queue, cpy_ctx);
        }
    }
}

static void on_recv(hio_t *io, void *buf, int readbytes)
{
    connector_con_state_t *cstate = (connector_con_state_t *)(hevent_userdata(io));

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    reserve(payload, readbytes);
    memcpy(rawBuf(payload), buf, readbytes);
    setLen(payload, readbytes);

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
        LOGD("Connector received close for FD:%x ",
             (int)hio_fd(io));
    else
        LOGD("Connector sent close for FD:%x ",
             (int)hio_fd(io));

    if (cstate != NULL)
    {
        tunnel_t *self = (cstate)->tunnel;
        line_t *line = (cstate)->line;
        context_t *context = newContext(line);
        context->fin = true;
        context->src_io = io;
        self->downStream(self, context);
    }
}

void onOutBoundConnected(hio_t *upstream_io)
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

    LOGD("Connector: connection succeed FD:%x [%s] <= [%s]",
         (int)hio_fd(upstream_io),
         SOCKADDR_STR(hio_localaddr(upstream_io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(upstream_io), peeraddrstr));

    context_t *est_context = newContext(line);
    est_context->est = true;
    est_context->src_io = upstream_io;
    self->downStream(self, est_context);
}

static void connectorUpStream(tunnel_t *self, context_t *c)
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
            assert(c->src_io != NULL);
            // hio_read_stop(c->src_io);

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
            cstate->io_back = c->src_io;

            socket_context_t *dest = &(c->dest_ctx);
            // sockaddr_set_ipport(&(dest->addr), "127.0.0.1", 443);
            // dest->protocol = IPPROTO_TCP;
            assert(dest->protocol == IPPROTO_TCP);
            LOGW("Connector: initiating connection");
            if (dest->atype == SAT_DOMAINNAME)
            {
                if (!dest->resolved)
                {
                    if (!resolve_domain(dest))
                    {
                        destroyContextQueue(cstate->queue);
                        free(CSTATE(c));
                        CSTATE_MUT(c) = NULL;
                        goto fail;
                    }
                }
            }

            hloop_t *loop = hevent_loop(c->src_io);

            int sockfd = socket(dest->addr.sa.sa_family, SOCK_STREAM, 0);
            if (sockfd < 0)
            {
                LOGE("Connector: socket fd < 0");
                destroyContextQueue(cstate->queue);
                free(CSTATE(c));
                CSTATE_MUT(c) = NULL;
                goto fail;
            }
            if (STATE(self)->no_delay)
            {
                tcp_nodelay(sockfd, 1);
            }
            hio_t *upstream_io = hio_get(loop, sockfd);
            assert(upstream_io != NULL);

            hio_set_peeraddr(upstream_io, &(dest->addr.sa), sockaddr_len(&(dest->addr)));
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
            destroyContextQueue(cstate->queue);
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
static void connectorDownStream(tunnel_t *self, context_t *c)
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
            cstate->write_paused = false;
            hio_read(cstate->io);
            resume_write_queue(cstate);

            self->dw->downStream(self->dw, c);

            // hio_read(cstate->io_back);
            // cstate->io_back = NULL;
        }
        else if (c->fin)
        {
            hio_t *io = CSTATE(c)->io;
            hevent_set_userdata(io, NULL);
            destroyContextQueue(cstate->queue);
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            self->dw->downStream(self->dw, c);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

static void connectorPacketUpStream(tunnel_t *self, context_t *c)
{
    connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        int bytes = bufLen(c->payload);

        if (c->dest_ctx.atype == SAT_DOMAINNAME)
        {
            if (!c->dest_ctx.resolved)
            {
                if (!resolve_domain(&(c->dest_ctx)))
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

static void connectorPacketDownStream(tunnel_t *self, context_t *c)
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

tunnel_t *newConnector(node_instance_context_t *instance_info)
{
    connector_state_t *state = malloc(sizeof(connector_state_t));
    memset(state, 0, sizeof(connector_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Connector->settings (object field) : The object was empty or invalid.");
        return NULL;
    }
    getBoolFromJsonObject(&(state->no_delay), settings, "nodelay");

    tunnel_t *t = newTunnel();
    t->state = state;

    t->upStream = &connectorUpStream;
    t->packetUpStream = &connectorPacketUpStream;
    t->downStream = &connectorDownStream;
    t->packetDownStream = &connectorPacketDownStream;

    atomic_thread_fence(memory_order_release);

    return t;
}
void apiConnector(tunnel_t *self, char *msg)
{
    LOGE("connector API NOT IMPLEMENTED"); // TODO
}
tunnel_t *destroyConnector(tunnel_t *self)
{
    LOGE("connector DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
