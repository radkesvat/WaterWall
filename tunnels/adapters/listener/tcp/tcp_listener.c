#include "tcp_listener.h"
#include "buffer_pool.h"
#include "wloop.h"
#include "loggers/network_logger.h"
#include "managers/socket_manager.h"
#include "tunnel.h"
#include "utils/jsonutils.h"

#include <string.h>
#include <time.h>

// enable profile to see some time info
// #define PROFILE 1
enum
{
    kDefaultKeepAliveTimeOutMs = 60 * 1000, // same as NGINX

    kEstablishedKeepAliveTimeOutMs = 360 * 1000 // since the connection is established,
                                                // other end timetout is probably shorter
};

typedef struct tcp_listener_state_s
{
    // settings
    char    *address;
    char   **white_list_raddr;
    char   **black_list_raddr;
    int      multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    bool     fast_open;
    bool     no_delay;
} tcp_listener_state_t;

typedef struct tcp_listener_con_state_s
{
    wloop_t         *loop;
    tunnel_t        *tunnel;
    line_t          *line;
    wio_t           *io;
    context_queue_t *data_queue;
    buffer_pool_t   *buffer_pool;
    bool             write_paused;
    bool             established;
    bool             first_packet_sent;
    bool             read_paused;
} tcp_listener_con_state_t;

static void cleanup(tcp_listener_con_state_t *cstate, bool flush_queue)
{
    if (cstate->io)
    {
        weventSetUserData(cstate->io, NULL);
        while (contextqueueLen(cstate->data_queue) > 0)
        {
            // all data must be written before sending fin, event loop will hold them for us
            context_t *cw = contextqueuePop(cstate->data_queue);

            if (flush_queue)
            {
                wioWrite(cstate->io, cw->payload);
                dropContexPayload(cw);
            }
            else
            {
                reuseContextPayload(cw);
            }
            destroyContext(cw);
        }
        wioClose(cstate->io);
    }
    if (cstate->write_paused)
    {
        resumeLineUpSide(cstate->line);
    }
    doneLineDownSide(cstate->line);
    contextqueueDestory(cstate->data_queue);
    lineDestroy(cstate->line);
    memoryFree(cstate);
}

static bool resumeWriteQueue(tcp_listener_con_state_t *cstate)
{
    context_queue_t *data_queue = (cstate)->data_queue;
    wio_t           *io         = cstate->io;
    while (contextqueueLen(data_queue) > 0)
    {
        context_t *cw     = contextqueuePop(data_queue);
        int        bytes  = (int) sbufGetBufLength(cw->payload);
        int        nwrite = wioWrite(io, cw->payload);
        dropContexPayload(cw);
        destroyContext(cw);
        if (nwrite >= 0 && nwrite < bytes)
        {
            return false; // write pending
        }
    }

    return true;
}

static void onWriteComplete(wio_t *io)
{
    // resume the read on other end of the connection
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (weventGetUserdata(io));
    if (UNLIKELY(cstate == NULL))
    {
        return;
    }

    if (wioCheckWriteComplete(io))
    {

        context_queue_t *data_queue = cstate->data_queue;
        if (contextqueueLen(data_queue) > 0 && ! resumeWriteQueue(cstate))
        {
            return;
        }
        wioSetCallBackWrite(cstate->io, NULL);
        cstate->write_paused = false;
        resumeLineUpSide(cstate->line);
    }
}

static void onLinePaused(void *userdata)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (userdata);

    if (! cstate->read_paused)
    {
        cstate->read_paused = true;
        wioReadStop(cstate->io);
    }
}

static void onLineResumed(void *userdata)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (userdata);

    if (cstate->read_paused)
    {
        cstate->read_paused = false;
        wioRead(cstate->io);
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
#ifdef PROFILE
    if (c->payload != NULL)
    {
        tcp_listener_con_state_t *cstate = CSTATE(c);

        bool *first_packet_sent = &((cstate)->first_packet_sent);

        if (! (*first_packet_sent))
        {
            *first_packet_sent = true;
            struct timeval tv1, tv2;
            getTimeOfDay(&tv1, NULL);
            {
                self->up->upStream(self->up, c);
            }
            getTimeOfDay(&tv2, NULL);
            double time_spent = (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec);
            LOGD("TcpListener: upstream took %d ms", (int) (time_spent * 1000));
            return;
        }
    }
#endif
    if (c->fin)
    {
        tcp_listener_con_state_t *cstate = CSTATE(c);
        CSTATE_DROP(c);
        cleanup(cstate, false);
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    tcp_listener_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->write_paused)
        {
            pauseLineUpSide(c->line);
            contextqueuePush(cstate->data_queue, c);
        }
        else
        {
            int bytes  = (int) sbufGetBufLength(c->payload);
            int nwrite = wioWrite(cstate->io, c->payload);
            dropContexPayload(c);

            if (nwrite >= 0 && nwrite < bytes)
            {
                pauseLineUpSide(c->line);
                cstate->write_paused = true;
                wioSetCallBackWrite(cstate->io, onWriteComplete);
            }
            destroyContext(c);
        }
    }
    else
    {
        if (c->fin)
        {
            CSTATE_DROP(c);
            cleanup(cstate, true);
            destroyContext(c);
        }
        else if (c->est)
        {
            assert(! cstate->established);
            cstate->established = true;
            wioSetKeepaliveTimeout(cstate->io, kEstablishedKeepAliveTimeOutMs);
            destroyContext(c);
        }
    }
}

static void onRecv(wio_t *io, sbuf_t *buf)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (weventGetUserdata(io));
    if (UNLIKELY(cstate == NULL))
    {
        bufferpoolResuesBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    sbuf_t *payload = buf;
    tunnel_t       *self    = (cstate)->tunnel;
    line_t         *line    = (cstate)->line;

    context_t *context = newContext(line);
    context->payload   = payload;

    self->upStream(self, context);
}
static void onClose(wio_t *io)
{
    tcp_listener_con_state_t *cstate = (tcp_listener_con_state_t *) (weventGetUserdata(io));
    if (cstate != NULL)
    {
        LOGD("TcpListener: received close for FD:%x ", wioGetFD(io));
        tunnel_t  *self    = (cstate)->tunnel;
        line_t    *line    = (cstate)->line;
        context_t *context = newFinContext(line);
        self->upStream(self, context);
    }
    else
    {
        LOGD("TcpListener: sent close for FD:%x ", wioGetFD(io));
    }
}

static void onInboundConnected(wevent_t *ev)
{
    wloop_t                *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *) weventGetUserdata(ev);
    wio_t                  *io   = data->io;
    size_t                  tid  = data->tid;
    wioAttach(loop, io);
    wioSetKeepaliveTimeout(io, kDefaultKeepAliveTimeOutMs);

    tunnel_t                 *self   = data->tunnel;
    line_t                   *line   = newLine(tid);
    tcp_listener_con_state_t *cstate = memoryAllocate(sizeof(tcp_listener_con_state_t));

    LSTATE_MUT(line)               = cstate;
    line->src_ctx.address_protocol = kSapTcp;
    line->src_ctx.address          = *(sockaddr_u *) wioGetPeerAddr(io);

    *cstate = (tcp_listener_con_state_t) {.line              = line,
                                          .buffer_pool       = getWorkerBufferPool(tid),
                                          .data_queue        = contextqueueCreate(),
                                          .io                = io,
                                          .tunnel            = self,
                                          .write_paused      = false,
                                          .established       = false,
                                          .first_packet_sent = false};

    setupLineDownSide(line, onLinePaused, cstate, onLineResumed);

    sockaddrSetPort(&(line->src_ctx.address), data->real_localport);
    line->src_ctx.address_type = line->src_ctx.address.sa.sa_family == AF_INET ? kSatIPV4 : kSatIPV6;
    weventSetUserData(io, cstate);

    if (loggerCheckWriteLevel(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        struct sockaddr log_localaddr = *wioGetLocaladdr(io);
        sockaddrSetPort((sockaddr_u *) &(log_localaddr), data->real_localport);

        LOGD("TcpListener: Accepted FD:%x  [%s] <= [%s]", wioGetFD(io), SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR(wioGetPeerAddr(io), peeraddrstr));
    }

    socketacceptresultDestroy(data);

    wioSetCallBackRead(io, onRecv);
    wioSetCallBackClose(io, onClose);

    // send the init packet
    lineLock(line);
    {
        context_t *context = newInitContext(line);
        self->upStream(self, context);
        if (! lineIsAlive(line))
        {
            LOGW("TcpListener: socket just got closed by upstream before anything happend");
            lineUnlock(line);
            return;
        }
    }
    lineUnlock(line);
    wioRead(io);
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
    tcp_listener_state_t *state = memoryAllocate(sizeof(tcp_listener_state_t));
    memorySet(state, 0, sizeof(tcp_listener_state_t));
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
    socket_filter_option_t filter_opt = {.no_delay = state->no_delay};

    getStringFromJsonObject(&(filter_opt.balance_group_name), settings, "balance-group");
    getIntFromJsonObject((int *) &(filter_opt.balance_group_interval), settings, "balance-interval");

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
            char **list = (char **) memoryAllocate(sizeof(char *) * (len + 1));
            memorySet((void *) list, 0, sizeof(char *) * (len + 1));
            list[len]              = 0x0;
            int          i         = 0;
            const cJSON *list_item = NULL;
            cJSON_ArrayForEach(list_item, wlist)
            {
                if (! getStringFromJson(&(list[i]), list_item) || ! verifyIPCdir(list[i], getNetworkLogger()))
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
    filter_opt.protocol         = kSapTcp;
    filter_opt.black_list_raddr = NULL;

    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    socketacceptorRegister(t, filter_opt, onInboundConnected);

    return t;
}

api_result_t apiTcpListener(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyTcpListener(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataTcpListener(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = kNodeFlagChainHead};
}
