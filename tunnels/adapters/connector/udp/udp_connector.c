#include "udp_connector.h"
#include "wplatform.h"
#include "loggers/network_logger.h"
#include "sync_dns.h"
#include "types.h"
#include "utils/jsonutils.h"


static void cleanup(udp_connector_con_state_t *cstate)
{
    memoryFree(cstate);
}
static void onRecvFrom(wio_t *io, sbuf_t *buf)
{
    udp_connector_con_state_t *cstate = (udp_connector_con_state_t *) (weventGetUserdata(io));
    if (UNLIKELY(cstate == NULL))
    {
        bufferpoolResuesBuffer(wloopGetBufferPool(weventGetLoop(io)), buf);
        return;
    }
    sbuf_t *payload = buf;
    tunnel_t       *self    = (cstate)->tunnel;
    line_t         *line    = (cstate)->line;

    if (! cstate->established)
    {
        cstate->established    = true;
        context_t *est_context = contextCreate(line);
        est_context->est       = true;
        self->downStream(self, est_context);
        if (weventGetUserdata(io) == NULL)
        {
            return;
        }
    }

    context_t *context = contextCreate(line);
    context->payload   = payload;
    self->downStream(self, context);
}

static void upStream(tunnel_t *self, context_t *c)
{
    udp_connector_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        if (wioIsClosed(cstate->io))
        {
            CSTATE_DROP(c);
            cleanup(cstate);
            contextReusePayload(c);
            goto fail;
        }

        size_t nwrite = wioWrite(cstate->io, c->payload);
        contextDropPayload(c);
        (void) nwrite;
        // assert(nwrite <= 0  || nwrite ==  bytes);
        contextDestroy(c);
    }
    else
    {
        if (c->init)
        {
            udp_connector_state_t *state = TSTATE(self);

            CSTATE_MUT(c) = memoryAllocate(sizeof(udp_connector_con_state_t));
            memorySet(CSTATE(c), 0, sizeof(udp_connector_con_state_t));
            cstate = CSTATE(c);

            cstate->buffer_pool = contextGetBufferPool(c);
            cstate->tunnel      = self;
            cstate->line        = c->line;
            // sockaddr_set_ipport(&(dest->addr),"www.gstatic.com",80);
            wloop_t   *loop      = getWorkerLoop(getWID());
            sockaddr_u host_addr = {0};
            sockaddrSetIpPort(&host_addr, "0.0.0.0", 0);

            int sockfd = socket(host_addr.sa.sa_family, SOCK_DGRAM, 0);
            if (sockfd < 0)
            {
                LOGE("Connector: socket fd < 0");
                CSTATE_DROP(c);
                cleanup(cstate);
                goto fail;
            }

#ifdef OS_UNIX
            so_reuseaddr(sockfd, 1);
#endif
            sockaddr_u addr;

            sockaddrSetIpPort(&addr, "0.0.0.0", 0);

            if (bind(sockfd, &addr.sa, sockaddrLen(&addr)) < 0)
            {
                LOGE("UDP bind failed;");
                closesocket(sockfd);
                goto fail;
            }

            wio_t *upstream_io = wioGet(loop, sockfd);
            assert(upstream_io != NULL);

            cstate->io = upstream_io;
            weventSetUserData(upstream_io, cstate);
            wioSetCallBackRead(upstream_io, onRecvFrom);
            wioRead(upstream_io);

            connection_context_t *dest_ctx = &(c->line->dest_ctx);
            connection_context_t *src_ctx  = &(c->line->src_ctx);
            switch ((enum udp_connector_dynamic_value_status) state->dest_addr_selected.status)
            {
            case kCdvsFromSource:
                connectionContextAddrCopy(dest_ctx, src_ctx);
                break;
            case kCdvsConstant:
                connectionContextAddrCopy(dest_ctx, &(state->constant_dest_addr));
                break;
            default:
            case kCdvsFromDest:
                break;
            }
            switch ((enum udp_connector_dynamic_value_status) state->dest_port_selected.status)
            {
            case kCdvsFromSource:
                connectionContextPortCopy(dest_ctx, src_ctx);
                break;
            case kCdvsConstant:
                connectionContextPortCopy(dest_ctx, &(state->constant_dest_addr));
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
                    CSTATE_DROP(c);
                    goto fail;
                }
            }
            wioSetPeerAddr(cstate->io, &(dest_ctx->address.sa), (int) sockaddrLen(&(dest_ctx->address)));

            contextDestroy(c);
        }
        else if (c->fin)
        {
            wio_t *io = cstate->io;
            weventSetUserData(io, NULL);
            cleanup(CSTATE(c));
            CSTATE_DROP(c);
            contextDestroy(c);
            wioClose(io);
        }
    }
    return;
fail:
    self->dw->downStream(self->dw, contextCreateFin(c->line));
    contextDestroy(c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    udp_connector_con_state_t *cstate = CSTATE(c);

    if (c->fin)
    {
        wio_t *io = cstate->io;
        weventSetUserData(io, NULL);
        CSTATE_DROP(c);
        cleanup(cstate);
    }
    self->dw->downStream(self->dw, c);
}

tunnel_t *newUdpConnector(node_instance_context_t *instance_info)
{
    udp_connector_state_t *state = memoryAllocate(sizeof(udp_connector_state_t));
    memorySet(state, 0, sizeof(udp_connector_state_t));
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

        if (state->constant_dest_addr.address_type == kSatDomainName)
        {
            connectionContextDomainSetConstMem(&(state->constant_dest_addr), state->dest_addr_selected.value_ptr,
                                           strlen(state->dest_addr_selected.value_ptr));
        }
        else
        {
            sockaddrSetIp(&(state->constant_dest_addr.address), state->dest_addr_selected.value_ptr);
        }
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
        connectionContextPortSet(&(state->constant_dest_addr), state->dest_port_selected.value);
    }
    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}
api_result_t apiUdpConnector(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyUdpConnector(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataUdpConnector(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
