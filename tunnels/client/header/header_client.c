#include "header_client.h"
#include "buffer_stream.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"

enum header_dynamic_value_status
{
    kHdvsEmpty = 0x0,
    kHdvsConstant,
    kHdvsSourcePort
};

typedef struct header_client_state_s
{
    dynamic_value_t data;

} header_client_state_t;

typedef struct header_client_con_state_s
{
    bool first_packet_received;
} header_client_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    header_client_state_t     *state  = TSTATE(self);
    header_client_con_state_t *cstate = CSTATE(c);
    if (c->init)
    {
        cstate        = globalMalloc(sizeof(header_client_con_state_t));
        *cstate       = (header_client_con_state_t) {0};
        CSTATE_MUT(c) = cstate;
    }
    else if (c->fin)
    {
        globalFree(cstate);
        CSTATE_DROP(c);
    }
    else if (! cstate->first_packet_received && c->payload != NULL)
    {
        cstate->first_packet_received = true;

        switch ((enum header_dynamic_value_status) state->data.status)
        {
        case kHdvsSourcePort:
            shiftl(c->payload, sizeof(uint16_t));
            writeUnAlignedUI16(c->payload, sockaddr_port(&(c->line->src_ctx.address)));
            break;

        default:
            break;
        }
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{

    if (c->fin)
    {
        globalFree( CSTATE(c));
        CSTATE_DROP(c);
    }

    self->dw->downStream(self->dw, c);
}

tunnel_t *newHeaderClient(node_instance_context_t *instance_info)
{

    header_client_state_t *state = globalMalloc(sizeof(header_client_state_t));
    memset(state, 0, sizeof(header_client_state_t));

    const cJSON *settings = instance_info->node_settings_json;
    state->data           = parseDynamicNumericValueFromJsonObject(settings, "data", 1, "src_context->port");

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiHeaderClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyHeaderClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataHeaderClient(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
