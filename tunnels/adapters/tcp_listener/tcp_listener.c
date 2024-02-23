#include "tcp_listener.h"
#include "buffer_pool.h"
#include "managers/socket_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include <time.h>
#include <string.h>

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

static void drain_queue(tcp_listener_con_state_t *cstate)
{
    context_queue_t *queue = (cstate)->queue;
    context_t **cw = &((cstate)->current_w);
    while (contextQueueLen(queue) > 0)
    {
        *cw = contextQueuePop(queue);
        reuseBuffer(cstate->buffer_pool, (*cw)->payload);
        (*cw)->payload = NULL;
        destroyContext((*cw));
        *cw = NULL;
    }
}

static bool resume_write_queue(tcp_listener_con_state_t *cstate)
{
    context_queue_t *queue = (cstate)->queue;
    context_t **cw = &((cstate)->current_w);
    hio_t *io = cstate->io;
    while (contextQueueLen(queue) > 0)
    {
        *cw = contextQueuePop(queue);
        if ((*cw)->src_io)
            hio_setup_upstream(io, (*cw)->src_io);
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
            destroyContext((*cw));

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

    hio_t *upstream_io = hio_get_upstream(io);
    if (hio_write_is_complete(io))
    {
        reuseBuffer(cstate->buffer_pool, (*cw)->payload);
        (*cw)->payload = NULL;
        destroyContext((*cw));
        *cw = NULL;

        if (resume_write_queue(cstate))
        {
            cstate->write_paused = false;
            hio_setcb_write(io, NULL);
            return;
        }
        if (upstream_io)
            hio_read(upstream_io);
    }
}

static inline void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
    }
    else
    {
        if (c->fin)
        {
            hio_t *io = CSTATE(c)->io;
            hevent_set_userdata(io, NULL);
            drain_queue(CSTATE(c));
            destroyContextQueue(CSTATE(c)->queue);
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
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
            if (c->src_io)
                hio_setup_upstream(cstate->io, c->src_io);
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
            return;
        }
        if (c->fin)
        {
            hio_t *io = CSTATE(c)->io;
            hevent_set_userdata(io, NULL);
            drain_queue(CSTATE(c));
            destroyContextQueue(CSTATE(c)->queue);
            destroyLine(c->line);
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
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

    shift_buffer_t *payload = popBuffer(cstate->buffer_pool);
    reserve(payload, readbytes);
    memcpy(rawBuf(payload), buf, readbytes);
    setLen(payload, readbytes);

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
        LOGD("TcpListener received close for FD:%x ",
             (int)hio_fd(io));
    else
        LOGD("TcpListener sent close for FD:%x ",
             (int)hio_fd(io));

    if (cstate != NULL)
    {
        tunnel_t *self = (cstate)->tunnel;
        line_t *line = (cstate)->line;
        context_t *context = newContext(line);
        context->fin = true;
        context->src_io = io;
        self->upStream(self, context);
    }
}
void onInboundConnected(hevent_t *ev)
{
    hloop_t *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *)hevent_userdata(ev);
    hio_t *io = data->io;
    size_t tid = data->tid;
    hio_attach(loop, io);
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};

    LOGD("TcpListener Accepted FD:%x [%s] <= [%s]",
         (int)hio_fd(io),
         SOCKADDR_STR(hio_localaddr(io), localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));

    tunnel_t *self = data->tunnel;

    line_t *line = newLine(tid);

    tcp_listener_con_state_t *cstate = malloc(sizeof(tcp_listener_con_state_t));
    cstate->queue = newContextQueue();
    cstate->line = line;
    cstate->line->loop = loop;
    cstate->buffer_pool = buffer_pools[tid];
    cstate->io = io;
    cstate->tunnel = self;
    cstate->current_w = NULL;
    cstate->write_paused = false;
    cstate->established = false;
    line->chains_state[self->chain_index] = cstate;

    hevent_set_userdata(io, cstate);

    // io->upstream_io = NULL;
    hio_setcb_read(io, on_recv);
    hio_setcb_close(io, on_close);
    // hio_setcb_write(io, on_write_complete); not required here

    // send the init packet
    context_t *context = newContext(line);
    context->init = true;
    context->src_io = io;
    self->upStream(self, context);
    if ((line->chains_state)[0] == NULL)
    {
        LOGW("Tcp socket just got closed by upstream before anything happend...");
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

    const cJSON *port = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if ((cJSON_IsNumber(port) && (port->valuedouble != 0)))
    {
        // single port given as a number
        STATE(t)->port_min = port->valuedouble;
        STATE(t)->port_max = port->valuedouble;
    }
    else
    {

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
    filter_opt.multiport_backend = multiport_backend_nothing;
    filter_opt.white_list_raddr = NULL;
    filter_opt.black_list_raddr = NULL;

    registerSocketAcceptor(t, filter_opt, onInboundConnected);

    t->upStream = &tcpListenerUpStream;
    t->packetUpStream = &tcpListenerPacketUpStream;
    t->downStream = &tcpListenerDownStream;
    t->packetDownStream = &tcpListenerPacketDownStream;

    atomic_thread_fence(memory_order_release);
    return t;
}

void apiTcpListener(tunnel_t *self, char *msg)
{
    LOGE("TcpListener API NOT IMPLEMENTED"); // TODO
}

tunnel_t *destroyTcpListener(tunnel_t *self)
{
    LOGE("TcpListener DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
