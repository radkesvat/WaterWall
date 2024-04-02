#include "tcp_listener.h"
#include "buffer_pool.h"
#include "managers/socket_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include <time.h>
#include <string.h>

// enable profile to see some time info
// #define PROFILE 1

#define STATE(x) ((tcp_listener_state_t *)((x)->state))
#define CSTATE(x) ((tcp_listener_con_state_t *)((((x)->line->chains_state)[self->chain_index])))

#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

typedef struct tcp_listener_state_s
{
    // settings
    char *address;
    int multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char **white_list_raddr;
    char **black_list_raddr;
    bool fast_open;
    bool no_delay;

} tcp_listener_state_t;

typedef struct tcp_listener_con_state_s
{
    hloop_t *loop;
    tunnel_t *tunnel;
    line_t *line;
    hio_t *io;
    context_queue_t *queue;
    context_t *current_w;
    buffer_pool_t *buffer_pool;
    bool write_paused;
    bool established;
    bool first_packet_sent;
} tcp_listener_con_state_t;

static void cleanup(tcp_listener_con_state_t *cstate)
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

static bool resume_write_queue(tcp_listener_con_state_t *cstate)
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
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *)(hevent_userdata(io));
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

static inline void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
#ifdef PROFILE
        if (c->first)
        {
            struct timeval tv1, tv2;
            gettimeofday(&tv1, NULL);
            {
                self->up->upStream(self->up, c);
            }
            gettimeofday(&tv2, NULL);
            double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 + (double)(tv2.tv_sec - tv1.tv_sec);
            LOGD("TcpListener: upstream took %d ms", (int)(time_spent * 1000));
            return;
        }

#endif
    }
    else
    {
        if (c->fin)
        {

            tcp_listener_con_state_t *cstate = CSTATE(c);
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
            destroyLine(c->line);
            hio_close(io);
        }
    }

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    tcp_listener_con_state_t *cstate = CSTATE(c);

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

        if (c->est)
        {
            cstate->established = true;
            destroyContext(c);

            return;
        }
        if (c->fin)
        {
            hio_t *io = cstate->io;
            hevent_set_userdata(io, NULL);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
            destroyLine(c->line);
            destroyContext(c);
            hio_close(io);

            return;
        }
    }
}

static void tcpListenerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void tcpListenerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void tcpListenerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void tcpListenerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

static void on_recv(hio_t *io, void *buf, int readbytes)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *)(hevent_userdata(io));
    if (cstate == NULL)
        return;
    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    setLen(payload, readbytes);
    memcpy(rawBuf(payload), buf, readbytes);

    tunnel_t *self = (cstate)->tunnel;
    line_t *line = (cstate)->line;
    bool *first_packet_sent = &((cstate)->first_packet_sent);

    context_t *context = newContext(line);
    context->src_io = io;
    context->payload = payload;
    if (!(*first_packet_sent))
    {
        *first_packet_sent = true;
        context->first = true;
    }

    self->upStream(self, context);
}
static void on_close(hio_t *io)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *)(hevent_userdata(io));
    if (cstate != NULL)
        LOGD("TcpListener: received close for FD:%x ",
             (int)hio_fd(io));
    else
        LOGD("TcpListener: sent close for FD:%x ",
             (int)hio_fd(io));

    if (cstate != NULL)
    {
        tunnel_t *self = (cstate)->tunnel;
        line_t *line = (cstate)->line;
        context_t *context = newFinContext(line);
        context->src_io = io;
        self->upStream(self, context);
    }
}
void on_inbound_connected(hevent_t *ev)
{
    hloop_t *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *)hevent_userdata(ev);
    hio_t *io = data->io;
    size_t tid = data->tid;
    hio_attach(loop, io);
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};

    tunnel_t *self = data->tunnel;
    line_t *line = newLine(tid);
    tcp_listener_con_state_t *cstate = malloc(sizeof(tcp_listener_con_state_t));
    cstate->line = line;
    cstate->buffer_pool = buffer_pools[tid];
    cstate->queue = newContextQueue(cstate->buffer_pool);
    cstate->io = io;
    cstate->tunnel = self;
    cstate->current_w = NULL;
    cstate->write_paused = false;
    cstate->established = false;
    cstate->first_packet_sent = false;
    line->chains_state[self->chain_index] = cstate;
    line->src_ctx.protocol = data->proto;
    line->src_ctx.addr.sa = *hio_peeraddr(io);
    sockaddr_set_port(&(line->src_ctx.addr), data->realport == 0 ? sockaddr_port((sockaddr_u *)hio_localaddr(io)) : data->realport);
    line->src_ctx.atype = line->src_ctx.addr.sa.sa_family == AF_INET ? SAT_IPV4 : SAT_IPV6;
    hevent_set_userdata(io, cstate);

    struct sockaddr log_localaddr = *hio_localaddr(io);
    sockaddr_set_port((sockaddr_u *)&(log_localaddr), data->realport == 0 ? sockaddr_port((sockaddr_u *)hio_localaddr(io)) : data->realport);

    LOGD("TcpListener: Accepted FD:%x [%s] <= [%s]",
         (int)hio_fd(io),
         SOCKADDR_STR(&log_localaddr, localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    free(data);

    // io->upstream_io = NULL;
    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    // hio_setcb_write(io, on_write_complete); not required here
    if (resume_write_queue(cstate))
        cstate->write_paused = false;
    else
        hio_setcb_write(cstate->io, on_write_complete);

    // send the init packet
    context_t *context = newInitContext(line);
    context->src_io = io;
    self->upStream(self, context);
    if ((line->chains_state)[0] == NULL)
    {
        LOGW("TcpListener: socket just got closed by upstream before anything happend...");
        return;
    }
    hio_read(io);
}

tunnel_t *newTcpListener(node_instance_context_t *instance_info)
{
    tunnel_t *t = newTunnel();
    t->state = malloc(sizeof(tcp_listener_state_t));
    memset(t->state, 0, sizeof(tcp_listener_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TcpListener->settings (object field) : The object was empty or invalid.");
        return NULL;
    }
    getBoolFromJsonObject(&(STATE(t)->no_delay), settings, "nodelay");

    if (!getStringFromJsonObject(&(STATE(t)->address), settings, "address"))
    {
        LOGF("JSON Error: TcpListener->settings->address (string field) : The data was empty or invalid.");
        return NULL;
    }

    int multiport_backend = multiport_backend_nothing;

    const cJSON *port = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if ((cJSON_IsNumber(port) && (port->valuedouble != 0)))
    {
        // single port given as a number
        STATE(t)->port_min = port->valuedouble;
        STATE(t)->port_max = port->valuedouble;
    }
    else
    {
        multiport_backend = multiport_backend_default;
        if (cJSON_IsArray(port))
        {
            const cJSON *port_minmax;
            int i = 0;
            // multi port given
            cJSON_ArrayForEach(port_minmax, port)
            {
                if (!(cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
                {
                    LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.");
                    LOGF("JSON Error: MultiPort parsing failed.");
                    return NULL;
                }
                if (i == 0)
                    STATE(t)->port_min = port_minmax->valuedouble;
                else if (i == 1)
                    STATE(t)->port_max = port_minmax->valuedouble;
                else
                {
                    LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.");
                    LOGF("JSON Error: MultiPort port range has more data than expected.");
                    return NULL;
                }

                i++;
            }

            dynamic_value_t dy_mb = parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
            if (dy_mb.status == 2)
                multiport_backend = multiport_backend_iptables;
            if (dy_mb.status == 3)
                multiport_backend = multiport_backend_sockets;
        }
        else
        {
            LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid.");
            return NULL;
        }
    }

    socket_filter_option_t filter_opt = {0};
    filter_opt.host = STATE(t)->address;
    filter_opt.port_min = STATE(t)->port_min;
    filter_opt.port_max = STATE(t)->port_max;
    filter_opt.proto = socket_protocol_tcp;
    filter_opt.multiport_backend = multiport_backend;
    filter_opt.white_list_raddr = NULL;
    filter_opt.black_list_raddr = NULL;

    registerSocketAcceptor(t, filter_opt, on_inbound_connected);

    t->upStream = &tcpListenerUpStream;
    t->packetUpStream = &tcpListenerPacketUpStream;
    t->downStream = &tcpListenerDownStream;
    t->packetDownStream = &tcpListenerPacketDownStream;

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiTcpListener(tunnel_t *self, char *msg)
{
    LOGE("TcpListener API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyTcpListener(tunnel_t *self)
{
    LOGE("TcpListener DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataTcpListener()
{
    return (tunnel_metadata_t){.version = 0001, .flags = TFLAG_ROUTE_STARTER};
}