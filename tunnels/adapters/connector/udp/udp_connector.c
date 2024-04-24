#include "loggers/network_logger.h"
#include "sync_dns.h"
#include "types.h"
#include "utils/sockutils.h"

static void cleanup(udp_connector_con_state_t *cstate)
{
    udp_connector_state_t *state = STATE(cstate->tunnel);
    free(cstate);
}
static void onRecv(hio_t *io, shift_buffer_t *buf)
{
    udp_connector_con_state_t *cstate = (udp_connector_con_state_t *) (hevent_userdata(io));

    shift_buffer_t *payload = buf;
    tunnel_t *      self    = (cstate)->tunnel;
    line_t *        line    = (cstate)->line;

    struct sockaddr *destaddr = hio_peeraddr(io);

    enum socket_address_type address_type;

    if (destaddr->sa_family == AF_INET6)
    {
        address_type = kSatIPV6;
    }
    else
    {
        address_type = kSatIPV4;
    }

    if (! cstate->established)
    {
        cstate->established    = true;
        context_t *est_context = newContext(line);
        est_context->est       = true;
        est_context->src_io    = io;
        self->downStream(self, est_context);
        if (hevent_userdata(io) == NULL)
        {
            return;
        }
    }

    context_t *context = newContext(line);
    context->src_io    = io;
    context->payload   = payload;

    self->downStream(self, context);
}

static void upStream(tunnel_t *self, context_t *c)
{
    udp_connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        unsigned int bytes = bufLen(c->payload);

        if (hio_is_closed(cstate->io))
        {
            cleanup(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            reuseContextBuffer(c);
            goto fail;
        }

        size_t nwrite = hio_write(cstate->io, c->payload);
        c->payload    = NULL;

        // assert(nwrite <= 0  || nwrite ==  bytes);
        destroyContext(c);
    }
    else
    {
        if (c->init)
        {
            udp_connector_state_t *state = STATE(self);

            CSTATE_MUT(c) = malloc(sizeof(udp_connector_con_state_t));
            memset(CSTATE(c), 0, sizeof(udp_connector_con_state_t));
            udp_connector_con_state_t *cstate = CSTATE(c);

            cstate->buffer_pool = getContextBufferPool(c);
            cstate->tunnel      = self;
            cstate->line        = c->line;
            // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);
            hloop_t *  loop      = loops[c->line->tid];
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
            hio_setcb_read(upstream_io, onRecv);
            hio_read(upstream_io);

            socket_context_t *dest_ctx = &(c->line->dest_ctx);
            socket_context_t *src_ctx  = &(c->line->src_ctx);
            switch (state->dest_addr_selected.status)
            {
            case kCdvsFromSource:
                socketContextAddrCopy(dest_ctx, src_ctx);
                break;
            case kCdvsConstant:
                socketContextAddrCopy(dest_ctx, &(state->constant_dest_addr));
                break;
            default:
            case kCdvsFromDest:
                break;
            }
            switch (state->dest_port_selected.status)
            {
            case kCdvsFromSource:
                socketContextPortCopy(dest_ctx, src_ctx);
                break;
            case kCdvsConstant:
                socketContextPortCopy(dest_ctx, &(state->constant_dest_addr));
                break;
            default:
            case kCdvsFromDest:
                break;
            }

            if (dest_ctx->address_type == kSatDomainName && ! dest_ctx->domain_resolved)
            {
                if (! resolveContextSync(dest_ctx))
                {
                    cleanup(CSTATE(c));
                    CSTATE_MUT(c) = NULL;
                    goto fail;
                }
            }
            hio_set_peeraddr(cstate->io, &(dest_ctx->addr.sa), sockaddr_len(&(dest_ctx->addr)));

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

static void downStream(tunnel_t *self, context_t *c)
{
    udp_connector_con_state_t *cstate = CSTATE(c);

    if (c->fin)
    {
        hio_t *io = cstate->io;
        hevent_set_userdata(io, NULL);
        cleanup(cstate);
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);
}

tunnel_t *newUdpConnector(node_instance_context_t *instance_info)
{
    udp_connector_state_t *state = malloc(sizeof(udp_connector_state_t));
    memset(state, 0, sizeof(udp_connector_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: UdpConnector->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    getBoolFromJsonObject(&(state->reuse_addr), settings, "reuseaddr");

    state->dest_addr_selected =
        parseDynamicStrValueFromJsonObject(settings, "address", 2, "src_context->address", "dest_context->address");

    if (state->dest_addr_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->address (string field) : The vaule was empty or invalid");
        return NULL;
    }
    if (state->dest_addr_selected.status == kDvsConstant)
    {
        state->constant_dest_addr.address_type = getHostAddrType(state->dest_addr_selected.value_ptr);
        socketContextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.value_ptr,
                               strlen(state->dest_addr_selected.value_ptr));
    }

    state->dest_port_selected =
        parseDynamicNumericValueFromJsonObject(settings, "port", 2, "src_context->port", "dest_context->port");

    if (state->dest_port_selected.status == kDvsEmpty)
    {
        LOGF("JSON Error: UdpConnector->settings->port (number field) : The vaule was empty or invalid");
        return NULL;
    }
    if (state->dest_port_selected.status == kDvsConstant)
    {
        socketContextPortSet(&(state->constant_dest_addr), state->dest_port_selected.value);
    }
    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    atomic_thread_fence(memory_order_release);
    return t;
}
api_result_t apiUdpConnector(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}
tunnel_t *destroyUdpConnector(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataUdpConnector()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}