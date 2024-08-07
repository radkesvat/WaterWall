#include "tun_listener.h"
#include "netif/tun."



typedef struct tun_listener_state_s
{
    // settings
    char    *device_address;

} tun_listener_state_t;

typedef struct tun_listener_con_state_s
{
    hloop_t         *loop;
    tunnel_t        *tunnel;
    line_t          *line;
    hio_t           *io;
    context_queue_t *data_queue;
    buffer_pool_t   *buffer_pool;
    bool             write_paused;
    bool             established;
    bool             first_packet_sent;
    bool             read_paused;
} tun_listener_con_state_t;

static void cleanup(tun_listener_con_state_t *cstate, bool write_queue)
{
 
    globalFree(cstate);
}

static bool resumeWriteQueue(tun_listener_con_state_t *cstate)
{
    context_queue_t *data_queue = (cstate)->data_queue;
    hio_t           *io         = cstate->io;
    while (contextQueueLen(data_queue) > 0)
    {
        context_t *cw     = contextQueuePop(data_queue);
        int        bytes  = (int) bufLen(cw->payload);
        int        nwrite = hio_write(io, cw->payload);
        dropContexPayload(cw);
        destroyContext(cw);
        if (nwrite >= 0 && nwrite < bytes)
        {
            return false; // write pending
        }
    }

    return true;
}

static void onWriteComplete(hio_t *io)
{
    // resume the read on other end of the connection
    tun_listener_con_state_t *cstate = (tun_listener_con_state_t *) (hevent_userdata(io));
    if (WW_UNLIKELY(cstate == NULL))
    {
        return;
    }

    if (hio_write_is_complete(io))
    {

        context_queue_t *data_queue = cstate->data_queue;
        if (contextQueueLen(data_queue) > 0 && ! resumeWriteQueue(cstate))
        {
            return;
        }
        hio_setcb_write(cstate->io, NULL);
        cstate->write_paused = false;
        resumeLineUpSide(cstate->line);
    }
}

static void onLinePaused(void *userdata)
{
    tun_listener_con_state_t *cstate = (tun_listener_con_state_t *) (userdata);

    if (! cstate->read_paused)
    {
        cstate->read_paused = true;
        hio_read_stop(cstate->io);
    }
}

static void onLineResumed(void *userdata)
{
    tun_listener_con_state_t *cstate = (tun_listener_con_state_t *) (userdata);

    if (cstate->read_paused)
    {
        cstate->read_paused = false;
        hio_read(cstate->io);
    }
}

static void upStream(tunnel_t *self, context_t *c)
{


}

static void downStream(tunnel_t *self, context_t *c)
{
    tun_listener_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->write_paused)
        {
            pauseLineUpSide(c->line);
            contextQueuePush(cstate->data_queue, c);
        }
        else
        {
            int bytes  = (int) bufLen(c->payload);
            int nwrite = hio_write(cstate->io, c->payload);
            dropContexPayload(c);

            if (nwrite >= 0 && nwrite < bytes)
            {
                pauseLineUpSide(c->line);
                cstate->write_paused = true;
                hio_setcb_write(cstate->io, onWriteComplete);
            }
            destroyContext(c);
        }
    }
    else
    {

        if (c->est)
        {
            assert(! cstate->established);
            cstate->established = true;
            hio_set_keepalive_timeout(cstate->io, kEstablishedKeepAliveTimeOutMs);
            destroyContext(c);
            return;
        }
        if (c->fin)
        {
            CSTATE_DROP(c);
            cleanup(cstate, true);
            destroyContext(c);
            return;
        }
    }
}

static void onRecv(hio_t *io, shift_buffer_t *buf)
{
    tun_listener_con_state_t *cstate = (tun_listener_con_state_t *) (hevent_userdata(io));
    if (WW_UNLIKELY(cstate == NULL))
    {
        reuseBuffer(hloop_bufferpool(hevent_loop(io)), buf);
        return;
    }
    shift_buffer_t *payload = buf;
    tunnel_t       *self    = (cstate)->tunnel;
    line_t         *line    = (cstate)->line;

    context_t *context = newContext(line);
    context->payload   = payload;

    self->upStream(self, context);
}
static void onClose(hio_t *io)
{
    tun_listener_con_state_t *cstate = (tun_listener_con_state_t *) (hevent_userdata(io));
    if (cstate != NULL)
    {
        LOGD("TunListener: received close for FD:%x ", hio_fd(io));
        tunnel_t  *self    = (cstate)->tunnel;
        line_t    *line    = (cstate)->line;
        context_t *context = newFinContext(line);
        self->upStream(self, context);
    }
    else
    {
        LOGD("TunListener: sent close for FD:%x ", hio_fd(io));
    }
}

static void onInboundConnected(hevent_t *ev)
{
    hloop_t                *loop = ev->loop;
    socket_accept_result_t *data = (socket_accept_result_t *) hevent_userdata(ev);
    hio_t                  *io   = data->io;
    size_t                  tid  = data->tid;
    hio_attach(loop, io);
    hio_set_keepalive_timeout(io, kDefaultKeepAliveTimeOutMs);

    tunnel_t                 *self   = data->tunnel;
    line_t                   *line   = newLine(tid);
    tun_listener_con_state_t *cstate = globalMalloc(sizeof(tun_listener_con_state_t));

    LSTATE_MUT(line)               = cstate;
    line->src_ctx.address_protocol = kSapTcp;
    line->src_ctx.address          = *(sockaddr_u *) hio_peeraddr(io);

    *cstate = (tun_listener_con_state_t) {.line              = line,
                                          .buffer_pool       = getWorkerBufferPool(tid),
                                          .data_queue        = newContextQueue(),
                                          .io                = io,
                                          .tunnel            = self,
                                          .write_paused      = false,
                                          .established       = false,
                                          .first_packet_sent = false};

    setupLineDownSide(line, onLinePaused, cstate, onLineResumed);

    sockaddr_set_port(&(line->src_ctx.address), data->real_localport);
    line->src_ctx.address_type = line->src_ctx.address.sa.sa_family == AF_INET ? kSatIPV4 : kSatIPV6;
    hevent_set_userdata(io, cstate);

    if (logger_will_write_level(getNetworkLogger(), LOG_LEVEL_DEBUG))
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};

        struct sockaddr log_localaddr = *hio_localaddr(io);
        sockaddr_set_port((sockaddr_u *) &(log_localaddr), data->real_localport);

        LOGD("TunListener: Accepted FD:%x  [%s] <= [%s]", hio_fd(io), SOCKADDR_STR(&log_localaddr, localaddrstr),
             SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    }

    destroySocketAcceptResult(data);

    hio_setcb_read(io, onRecv);
    hio_setcb_close(io, onClose);

    // send the init packet
    lockLine(line);
    {
        context_t *context = newInitContext(line);
        self->upStream(self, context);
        if (! isAlive(line))
        {
            LOGW("TunListener: socket just got closed by upstream before anything happend");
            unLockLine(line);
            return;
        }
    }
    unLockLine(line);
    hio_read(io);
}

static void parsePortSection(tun_listener_state_t *state, const cJSON *settings)
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
                    LOGF("JSON Error: TunListener->settings->port (number-or-array field) : The data was empty or "
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
            LOGF("JSON Error: TunListener->settings->port (number-or-array field) : The data was empty or invalid");
            exit(1);
        }
    }
}

tunnel_t *newTunListener(node_instance_context_t *instance_info)
{
    tun_listener_state_t *state = globalMalloc(sizeof(tun_listener_state_t));
    memset(state, 0, sizeof(tun_listener_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TunListener->settings (object field) : The object was empty or invalid");
        return NULL;
    }
    getBoolFromJsonObject(&(state->no_delay), settings, "nodelay");

    if (! getStringFromJsonObject(&(state->address), settings, "address"))
    {
        LOGF("JSON Error: TunListener->settings->address (string field) : The data was empty or invalid");
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
            char **list = (char **) globalMalloc(sizeof(char *) * (len + 1));
            memset((void *) list, 0, sizeof(char *) * (len + 1));
            list[len]              = 0x0;
            int          i         = 0;
            const cJSON *list_item = NULL;
            cJSON_ArrayForEach(list_item, wlist)
            {
                if (! getStringFromJson(&(list[i]), list_item) || ! verifyIpCdir(list[i], getNetworkLogger()))
                {
                    LOGF("JSON Error: TunListener->settings->whitelist (array of strings field) index %d : The data "
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

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    registerSocketAcceptor(t, filter_opt, onInboundConnected);

    return t;
}

api_result_t apiTunListener(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyTunListener(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataTunListener(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = kNodeFlagChainHead};
}
