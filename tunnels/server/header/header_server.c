#include "header_server.h"
#include "buffer_stream.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"

enum header_dynamic_value_status
{
    kHdvsEmpty = 0x0,
    kHdvsConstant,
    kHdvsDestPort,
};

typedef struct header_server_state_s
{
    dynamic_value_t data;

} header_server_state_t;

typedef struct header_server_con_state_s
{
    bool            init_sent;
    shift_buffer_t *buf;

} header_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    header_server_state_t     *state  = TSTATE(self);
    header_server_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        if (! cstate->init_sent)
        {
            if (cstate->buf)
            {
                c->payload  = appendBufferMerge(getContextBufferPool(c), cstate->buf, c->payload);
                cstate->buf = NULL;
            }

            shift_buffer_t *buf = c->payload;

            switch ((enum header_dynamic_value_status) state->data.status)
            {
            case kHdvsDestPort:;

                uint16_t port = 0;
                if (bufLen(c->payload) < 2)
                {
                    cstate->buf = c->payload;
                    dropContexPayload(c);
                    destroyContext(c);
                    return;
                }

                readUI16(buf, &port);
                sockaddr_set_port(&(c->line->dest_ctx.address), port);
                shiftr(c->payload, sizeof(uint16_t));
                if (port < 10)
                {
                    reuseContextPayload(c);
                    self->dw->downStream(self->dw, newFinContext(c->line));
                    destroyContext(c);
                    return;
                }
                break;
            default:
                break;
            }

            cstate->init_sent = true;
            self->up->upStream(self->up, newInitContext(c->line));
            if (bufLen(buf) > 0)
            {
                if (! isAlive(c->line))
                {
                    reuseContextPayload(c);
                    destroyContext(c);
                    return;
                }
            }
            else
            {
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }
        self->up->upStream(self->up, c);
    }
    else if (c->init)
    {
        cstate        = wwmGlobalMalloc(sizeof(header_server_con_state_t));
        *cstate       = (header_server_con_state_t) {0};
        CSTATE_MUT(c) = cstate;
        destroyContext(c);
    }
    else if (c->fin)
    {
        bool send_fin = cstate->init_sent;
        if (cstate->buf)
        {
            reuseBuffer(getContextBufferPool(c), cstate->buf);
        }
        wwmGlobalFree(cstate);
        CSTATE_DROP(c);
        if (send_fin)
        {
            self->up->upStream(self->up, c);
        }
        else
        {
            destroyContext(c);
        }
    }
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->fin)
    {
        header_server_con_state_t *cstate = CSTATE(c);
        if (cstate->buf)
        {
            reuseBuffer(getContextBufferPool(c), cstate->buf);
        }

        wwmGlobalFree(cstate);
        CSTATE_DROP(c);
    }

    self->dw->downStream(self->dw, c);
}

tunnel_t *newHeaderServer(node_instance_context_t *instance_info)
{

    header_server_state_t *state = wwmGlobalMalloc(sizeof(header_server_state_t));
    memset(state, 0, sizeof(header_server_state_t));
    const cJSON *settings = instance_info->node_settings_json;
    state->data           = parseDynamicNumericValueFromJsonObject(settings, "override", 1, "dest_context->port");
    tunnel_t *t           = newTunnel();
    t->state              = state;
    t->upStream           = &upStream;
    t->downStream         = &downStream;

    return t;
}

api_result_t apiHeaderServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHeaderServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataHeaderServer(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
