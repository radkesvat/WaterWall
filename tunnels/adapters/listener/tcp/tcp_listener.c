#include "tcp_listener.h"
#include "buffer_pool.h"
#include "loggers/network_logger.h"
#include "managers/socket_manager.h"
#include "utils/jsonutils.h"
#include "utils/sockutils.h"
#include <string.h>
#include <time.h>

// enable profile to see some time info
// #define PROFILE 1

typedef struct tcp_listener_state_s
{
    // settings
    char    *address;
    int      multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char   **white_list_raddr;
    char   **black_list_raddr;
    bool     fast_open;
    bool     no_delay;

} tcp_listener_state_t;

typedef struct tcp_listener_con_state_s
{
    hloop_t         *loop;
    tunnel_t        *tunnel;
    line_t          *line;
    hio_t           *io;
    context_queue_t *finished_queue;
    context_queue_t *data_queue;
    buffer_pool_t   *buffer_pool;
    bool             write_paused;
    bool             established;
    bool             first_packet_sent;
} tcp_listener_con_state_t;

static void cleanup(tcp_listener_con_state_t *cstate, bool write_queue)
{
    if (cstate->io)
    {
        hevent_set_userdata(cstate->io, NULL);
    }

    hio_t *last_resumed_io = NULL;

    while (contextQueueLen(cstate->data_queue) > 0)
    {
        context_t *cw = contextQueuePop(cstate->data_queue);
        if (cw->src_io != NULL && last_resumed_io != cw->src_io)
        {
            last_resumed_io = cw->src_io;
            hio_read(cw->src_io);
        }
        if (write_queue)
        {
            hio_write(cstate->io, cw->payload);
            cw->payload = NULL;
        }
        else
        {
            reuseContextBuffer(cw);
        }
        destroyContext(cw);
    }

    while (contextQueueLen(cstate->finished_queue) > 0)
    {
        context_t *cw = contextQueuePop(cstate->finished_queue);
        if (cw->src_io != NULL && last_resumed_io != cw->src_io)
        {
            last_resumed_io = cw->src_io;
            hio_read(cw->src_io);
        }

        destroyContext(cw);
    }

    destroyContextQueue(cstate->data_queue);
    destroyContextQueue(cstate->finished_queue);
    free(cstate);
}

static bool resumeWriteQueue(tcp_listener_con_state_t *cstate)
{
    context_queue_t *data_queue     = (cstate)->data_queue;
    context_queue_t *finished_queue = (cstate)->finished_queue;
    hio_t           *io             = cstate->io;
    while (contextQueueLen(data_queue) > 0)
    {
        context_t   *cw     = contextQueuePop(data_queue);
        unsigned int bytes  = bufLen(cw->payload);
        int          nwrite = hio_write(io, cw->payload);
        cw->payload         = NULL;
        contextQueuePush(cstate->finished_queue, cw);
        if (nwrite >= 0 && nwrite < bytes)
        {
            return false; // write pending
        }
    }
    // data queue is empty
    hio_t *last_resumed_io = NULL;
    while (contextQueueLen(finished_queue) > 0)
    {
        context_t *cw          = contextQueuePop(finished_queue);
        hio_t     *upstream_io = cw->src_io;
        if (upstream_io != NULL && (last_resumed_io != upstream_io))
        {
            last_resumed_io = upstream_io;
            hio_read(upstream_io);
        }
        destroyContext(cw);
    }
    return true;
}

static void onWriteComplete(hio_t *restrict io)
{
    // resume the read on other end of the connection
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (hevent_userdata(io));
    if (cstate == NULL)
    {
        return;
    }

    if (hio_write_is_complete(io))
    {
        hio_setcb_write(cstate->io, NULL);
        cstate->write_paused = false;

        context_queue_t *data_queue     = cstate->data_queue;
        context_queue_t *finished_queue = cstate->finished_queue;
        if (contextQueueLen(data_queue) > 0)
        {
            if (! resumeWriteQueue(cstate))
            {
                hio_setcb_write(cstate->io, onWriteComplete);
                cstate->write_paused = true;
                return;
            }
        }

        hio_t *last_resumed_io = NULL;
        while (contextQueueLen(finished_queue) > 0)
        {
            context_t *cw          = contextQueuePop(finished_queue);
            hio_t     *upstream_io = cw->src_io;
            if (upstream_io != NULL && (last_resumed_io != upstream_io))
            {
                last_resumed_io = upstream_io;
                hio_read(upstream_io);
            }
            destroyContext(cw);
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
            double time_spent = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);
            LOGD("TcpListener: upstream took %d ms", (int) (time_spent * 1000));
            return;
        }
#endif
    }
    else
    {
        if (c->fin)
        {

            tcp_listener_con_state_t *cstate = CSTATE(c);
            cleanup(cstate, false);
            CSTATE_MUT(c) = NULL;
            destroyLine(c->line);
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
            {
                hio_read_stop(c->src_io);
            }
            contextQueuePush(cstate->data_queue, c);
        }
        else
        {
            unsigned int bytes  = bufLen(c->payload);
            int          nwrite = hio_write(cstate->io, c->payload);
            c->payload          = NULL;
            if (nwrite >= 0 && nwrite < bytes)
            {
                if (c->src_io)
                {
                    hio_read_stop(c->src_io);
                }
                contextQueuePush(cstate->finished_queue, c);
                cstate->write_paused = true;
                hio_setcb_write(cstate->io, onWriteComplete);
            }
            else
            {
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
            hio_t *io     = cstate->io;
            CSTATE_MUT(c) = NULL;
            contextQueueNotifyIoRemoved(cstate->data_queue, c->src_io);
            contextQueueNotifyIoRemoved(cstate->finished_queue, c->src_io);
            cleanup(cstate, true);
            destroyLine(c->line);
            destroyContext(c);
            hio_close(io);
            return;
        }
    }
}

static void onRecv(hio_t *io, shift_buffer_t *buf)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (hevent_userdata(io));
    if (cstate == NULL)
    {
        reuseBuffer(hloop_bufferpool(hevent_loop(io)), buf);
        return;
    }
    shift_buffer_t *payload           = buf;
    tunnel_t       *self              = (cstate)->tunnel;
    line_t         *line              = (cstate)->line;
    bool           *first_packet_sent = &((cstate)->first_packet_sent);

    context_t *context = newContext(line);
    context->src_io    = io;
    context->payload   = payload;
    if (! (*first_packet_sent))
    {
        *first_packet_sent = true;
        context->first     = true;
    }

    self->upStream(self, context);
}
static void onClose(hio_t *io)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (hevent_userdata(io));
    if (cstate != NULL)
    {
        LOGD("TcpListener: received close for FD:%x ", (int) hio_fd(io));
    }
    else
    {
        LOGD("TcpListener: sent close for FD:%x ", (int) hio_fd(io));
    }

    if (cstate != NULL)
    {
        tunnel_t  *self    = (cstate)->tunnel;
        line_t    *line    = (cstate)->line;
        context_t *context = newFinContext(line);
        self->upStream(self, context);
    }
}

static void onInboundConnected(hevent_t *ev)
{
    hloop_t                *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *) hevent_userdata(ev);
    hio_t                  *io   = data->io;
    size_t                  tid  = data->tid;
    hio_attach(loop, io);
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};

    tunnel_t                 *self        = data->tunnel;
    line_t                   *line        = newLine(tid);
    tcp_listener_con_state_t *cstate      = malloc(sizeof(tcp_listener_con_state_t));
    cstate->line                          = line;
    cstate->buffer_pool                   = getThreadBufferPool(tid);
    cstate->finished_queue                = newContextQueue(cstate->buffer_pool);
    cstate->data_queue                    = newContextQueue(cstate->buffer_pool);
    cstate->io                            = io;
    cstate->tunnel                        = self;
    cstate->write_paused                  = false;
    cstate->established                   = false;
    cstate->first_packet_sent             = false;
    line->chains_state[self->chain_index] = cstate;
    line->src_ctx.address_protocol        = kSapTcp;
    line->src_ctx.address                 = *(sockaddr_u *) hio_peeraddr(io);

    // sockaddr_set_port(&(line->src_ctx.addr), data->real_localport == 0 ? sockaddr_port((sockaddr_u
    // *)hio_localaddr(io)) : data->real_localport);
    sockaddr_set_port(&(line->src_ctx.address), data->real_localport);
    line->src_ctx.address_type = line->src_ctx.address.sa.sa_family == AF_INET ? kSatIPV4 : kSatIPV6;
    hevent_set_userdata(io, cstate);

    struct sockaddr log_localaddr = *hio_localaddr(io);
    sockaddr_set_port((sockaddr_u *) &(log_localaddr), data->real_localport);

    LOGD("TcpListener: Accepted FD:%x  [%s] <= [%s]", (int) hio_fd(io), SOCKADDR_STR(&log_localaddr, localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    free(data);

    // io->upstream_io = NULL;
    hio_setcb_read(io, onRecv);
    hio_setcb_close(io, onClose);
    // hio_setcb_write(io, onWriteComplete); not required here
    if (resumeWriteQueue(cstate))
    {
        cstate->write_paused = false;
    }
    else
    {
        hio_setcb_write(cstate->io, onWriteComplete);
    }

    // send the init packet
    context_t *context = newInitContext(line);
    context->src_io    = io;
    self->upStream(self, context);
    if (! isAlive(line))
    {
        LOGW("TcpListener: socket just got closed by upstream before anything happend");
        return;
    }
    hio_read(io);
}

static void parsePortSection(tcp_listener_state_t *state, const cJSON *settings)
{
    const cJSON *port_json = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if ((cJSON_IsNumber(port_json) && (port_json->valuedouble != 0)))
    {
        // single port given as a number
        state->port_min = (int) port_json->valuedouble;
        state->port_max = (int) port_json->valuedouble;
    }
    else
    {
        if (cJSON_IsArray(port_json) && cJSON_GetArraySize(port_json) == 2)
        {
            // multi port given
            const cJSON *port_minmax;
            int          i = 0;
            cJSON_ArrayForEach(port_minmax, port_json)
            {
                if (! (cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
                {
                    LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or "
                         "invalid");
                    exit(1);
                }
                if (i == 0)
                {
                    state->port_min = (int) port_minmax->valuedouble;
                }
                else if (i == 1)
                {
                    state->port_max = (int) port_minmax->valuedouble;
                }

                i++;
            }
        }
        else
        {
            LOGF("JSON Error: TcpListener->settings->port (number-or-array field) : The data was empty or invalid");
            exit(1);
        }
    }
}
tunnel_t *newTcpListener(node_instance_context_t *instance_info)
{
    tcp_listener_state_t *state = malloc(sizeof(tcp_listener_state_t));
    memset(state, 0, sizeof(tcp_listener_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TcpListener->settings (object field) : The object was empty or invalid");
        return NULL;
    }
    getBoolFromJsonObject(&(state->no_delay), settings, "nodelay");

    if (! getStringFromJsonObject(&(state->address), settings, "address"))
    {
        LOGF("JSON Error: TcpListener->settings->address (string field) : The data was empty or invalid");
        return NULL;
    }
    socket_filter_option_t filter_opt = {0};

    filter_opt.multiport_backend = kMultiportBackendNothing;
    parsePortSection(state, settings);
    if (state->port_max != 0)
    {
        filter_opt.multiport_backend = kMultiportBackendDefault;
        dynamic_value_t dy_mb =
            parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
        if (dy_mb.status == 2)
        {
            filter_opt.multiport_backend = kMultiportBackendIptables;
        }
        if (dy_mb.status == 3)
        {
            filter_opt.multiport_backend = kMultiportBackendSockets;
        }
    }

    filter_opt.white_list_raddr = NULL;
    const cJSON *wlist          = cJSON_GetObjectItemCaseSensitive(settings, "whitelist");
    if (cJSON_IsArray(wlist))
    {
        size_t len = cJSON_GetArraySize(wlist);
        if (len > 0)
        {
            char **list = (char **) malloc(sizeof(char *) * (len + 1));
            memset((void *) list, 0, sizeof(char *) * (len + 1));
            list[len]              = 0x0;
            int          i         = 0;
            const cJSON *list_item = NULL;
            cJSON_ArrayForEach(list_item, wlist)
            {
                unsigned int list_item_len = 0;
                if (! getStringFromJson(&(list[i]), list_item) || ! verifyIpCdir(list[i], getNetworkLogger()))
                {
                    LOGF("JSON Error: TcpListener->settings->whitelist (array of strings field) index %d : The data "
                         "was empty or invalid",
                         i);
                    exit(1);
                }

                i++;
            }

            filter_opt.white_list_raddr = list;
        }
    }

    filter_opt.host             = state->address;
    filter_opt.port_min         = state->port_min;
    filter_opt.port_max         = state->port_max;
    filter_opt.proto            = kSapTcp;
    filter_opt.black_list_raddr = NULL;

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    registerSocketAcceptor(t, filter_opt, onInboundConnected);

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiTcpListener(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyTcpListener(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataTcpListener()
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}