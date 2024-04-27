#include "udp_listener.h"
#include "buffer_pool.h"
#include "idle_table.h"
#include "loggers/network_logger.h"
#include "managers/socket_manager.h"
#include "utils/jsonutils.h"
#include <string.h>
#include <time.h>

// enable profile to see some time info
// #define PROFILE 1

typedef struct udp_listener_state_s
{
    // settings
    char    *address;
    int      multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char   **white_list_raddr;
    char   **black_list_raddr;

} udp_listener_state_t;

typedef struct udp_listener_con_state_s
{
    hloop_t       *loop;
    tunnel_t      *tunnel;
    line_t        *line;
    hio_t         *io;
    buffer_pool_t *buffer_pool;
    bool           established;
    bool           first_packet_sent;
} udp_listener_con_state_t;

static void cleanup(udp_listener_con_state_t *cstate)
{
    if (cstate->io)
    {
        hevent_set_userdata(cstate->io, NULL);
    }

    free(cstate);
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
            LOGD("UdpListener: upstream took %d ms", (int) (time_spent * 1000));
            return;
        }
#endif
    }
    else
    {
        if (c->fin)
        {

            udp_listener_con_state_t *cstate = CSTATE(c);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
            destroyLine(c->line);
        }
    }

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    udp_listener_con_state_t *cstate = CSTATE(c);

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
            cleanup(cstate);
            destroyLine(c->line);
            destroyContext(c);
            hio_close(io);
            return;
        }
    }
}

static void onRecvFrom(hio_t *io, shift_buffer_t *buf)
{

    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
    printf("[%s] <=> [%s]\n", SOCKADDR_STR(hio_localaddr(io), localaddrstr),
           SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));

    hash_t peer_hash =  sockAddrCalcHash(hio_peeraddr(io));   
    
      
    line_t                   *line        = newLine(tid);
    udp_listener_con_state_t *cstate = (udp_listener_con_state_t *) (hevent_userdata(io));




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
    udp_listener_con_state_t *cstate = (udp_listener_con_state_t *) (hevent_userdata(io));
    if (cstate != NULL)
    {
        LOGD("UdpListener: received close for FD:%x ", (int) hio_fd(io));
    }
    else
    {
        LOGD("UdpListener: sent close for FD:%x ", (int) hio_fd(io));
    }

    if (cstate != NULL)
    {
        tunnel_t  *self    = (cstate)->tunnel;
        line_t    *line    = (cstate)->line;
        context_t *context = newFinContext(line);
        self->upStream(self, context);
    }
}

void onInboundConnected(hevent_t *ev)
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
    udp_listener_con_state_t *cstate      = malloc(sizeof(udp_listener_con_state_t));
    cstate->line                          = line;
    cstate->buffer_pool                   = getThreadBufferPool(tid);
    cstate->io                            = io;
    cstate->tunnel                        = self;
    cstate->established                   = false;
    cstate->first_packet_sent             = false;
    line->chains_state[self->chain_index] = cstate;
    line->src_ctx.address_protocol        = data->proto;
    line->src_ctx.address.sa              = *hio_peeraddr(io);

    // sockaddr_set_port(&(line->src_ctx.addr), data->real_localport == 0 ? sockaddr_port((sockaddr_u
    // *)hio_localaddr(io)) : data->real_localport);
    sockaddr_set_port(&(line->src_ctx.address), data->real_localport);
    line->src_ctx.address_type = line->src_ctx.address.sa.sa_family == AF_INET ? kSatIPV4 : kSatIPV6;
    hevent_set_userdata(io, cstate);

    struct sockaddr log_localaddr = *hio_localaddr(io);
    sockaddr_set_port((sockaddr_u *) &(log_localaddr), data->real_localport);

    LOGD("UdpListener: Accepted FD:%x  [%s] <= [%s]", (int) hio_fd(io), SOCKADDR_STR(&log_localaddr, localaddrstr),
         SOCKADDR_STR(hio_peeraddr(io), peeraddrstr));
    free(data);

    hio_setcb_read(io, onRecv);
    hio_setcb_close(io, onClose);

    // send the init packet
    context_t *context = newInitContext(line);
    context->src_io    = io;
    self->upStream(self, context);
    if (! isAlive(line))
    {
        LOGW("UdpListener: socket just got closed by upstream before anything happend");
        return;
    }
    hio_read(io);
}

tunnel_t *newUdpListener(node_instance_context_t *instance_info)
{
    udp_listener_state_t *state = malloc(sizeof(udp_listener_state_t));
    memset(state, 0, sizeof(udp_listener_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: UdpListener->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->address), settings, "address"))
    {
        LOGF("JSON Error: UdpListener->settings->address (string field) : The data was empty or invalid");
        return NULL;
    }

    int multiport_backend = kMultiportBackendNothing;

    const cJSON *port = cJSON_GetObjectItemCaseSensitive(settings, "port");
    if ((cJSON_IsNumber(port) && (port->valuedouble != 0)))
    {
        // single port given as a number
        state->port_min = port->valuedouble;
        state->port_max = port->valuedouble;
    }
    else
    {
        multiport_backend = kMultiportBackendDefault;
        if (cJSON_IsArray(port))
        {
            const cJSON *port_minmax;
            int          i = 0;
            // multi port given
            cJSON_ArrayForEach(port_minmax, port)
            {
                if (! (cJSON_IsNumber(port_minmax) && (port_minmax->valuedouble != 0)))
                {
                    LOGF("JSON Error: UdpListener->settings->port (number-or-array field) : The data was empty or "
                         "invalid");
                    LOGF("JSON Error: MultiPort parsing failed");
                    return NULL;
                }
                if (i == 0)
                {
                    state->port_min = port_minmax->valuedouble;
                }
                else if (i == 1)
                {
                    state->port_max = port_minmax->valuedouble;
                }
                else
                {
                    LOGF("JSON Error: UdpListener->settings->port (number-or-array field) : The data was empty or "
                         "invalid");
                    LOGF("JSON Error: MultiPort port range has more data than expected");
                    return NULL;
                }

                i++;
            }

            dynamic_value_t dy_mb =
                parseDynamicStrValueFromJsonObject(settings, "multiport-backend", 2, "iptables", "socket");
            if (dy_mb.status == 2)
            {
                multiport_backend = kMultiportBackendIptables;
            }
            if (dy_mb.status == 3)
            {
                multiport_backend = kMultiportBackendSockets;
            }
        }
        else
        {
            LOGF("JSON Error: UdpListener->settings->port (number-or-array field) : The data was empty or invalid");
            return NULL;
        }
    }
    socket_filter_option_t filter_opt = {0};

    filter_opt.white_list_raddr = NULL;
    const cJSON *wlist          = cJSON_GetObjectItemCaseSensitive(settings, "whitelist");
    if (cJSON_IsArray(wlist))
    {
        size_t len = cJSON_GetArraySize(wlist);
        if (len > 0)
        {
            char **list = malloc(sizeof(char *) * (len + 1));
            memset(list, 0, sizeof(char *) * (len + 1));
            list[len]              = 0x0;
            int          i         = 0;
            const cJSON *list_item = NULL;
            cJSON_ArrayForEach(list_item, wlist)
            {
                unsigned int list_item_len = 0;
                if (! getStringFromJson(&(list[i]), list_item) || (list_item_len = strlen(list[i])) < 4)
                {
                    LOGF("JSON Error: UdpListener->settings->whitelist (array of strings field) index %d : The data "
                         "was empty or invalid",
                         i);
                    exit(1);
                }
                char *slash = strchr(list[i], '/');
                if (slash == NULL)
                {
                    LOGF("Value Error: whitelist %d : Subnet prefix is missing in ip. \"%s\" + /xx", i, list[i]);
                    exit(1);
                }
                *slash = '\0';
                if (! is_ipaddr(list[i]))
                {
                    LOGF("Value Error: whitelist %d : \"%s\" is not a valid ip address", i, list[i]);
                    exit(1);
                }

                bool is_v4 = is_ipv4(list[i]);
                *slash     = '/';

                char *subnet_part   = slash + 1;
                int   prefix_length = atoi(subnet_part);

                if (is_v4 && (prefix_length < 0 || prefix_length > 32))
                {
                    LOGF("Value Error: Invalid subnet mask length for ipv4 %s prefix %d must be between 0 and 32",
                         list[i], prefix_length);
                    exit(1);
                }
                if (! is_v4 && (prefix_length < 0 || prefix_length > 128))
                {
                    LOGF("Value Error: Invalid subnet mask length for ipv6 %s prefix %d must be between 0 and 128",
                         list[i], prefix_length);
                    exit(1);
                }
                if (prefix_length > 0 && slash + 2 + (int) (log10(prefix_length)) < list[i] + list_item_len)
                {
                    LOGW("the value \"%s\" looks incorrect, it has more data than ip/prefix", list[i]);
                }
                i++;
            }

            filter_opt.white_list_raddr = list;
        }
    }

    filter_opt.host              = state->address;
    filter_opt.port_min          = state->port_min;
    filter_opt.port_max          = state->port_max;
    filter_opt.proto             = kSapUdp;
    filter_opt.multiport_backend = multiport_backend;
    filter_opt.black_list_raddr  = NULL;

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    registerSocketAcceptor(t, filter_opt, onInboundConnected);

    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiUdpListener(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyUdpListener(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataUdpListener()
{
    return (tunnel_metadata_t){.version = 0001, .flags = kNodeFlagChainHead};
}