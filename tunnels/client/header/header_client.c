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
    void *_;
} header_client_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    header_client_state_t *state = STATE(self);

    if (c->first && c->payload != NULL)
    {

        switch ((enum header_dynamic_value_status) state->data.status)
        {
        case kHdvsSourcePort:
            shiftl(c->payload, sizeof(uint16_t));
            writeUI16(c->payload, sockaddr_port(&(c->line->src_ctx.address)));
            break;

        default:
            break;
        }
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{

    self->dw->downStream(self->dw, c);
}

tunnel_t *newHeaderClient(node_instance_context_t *instance_info)
{

    header_client_state_t *state = wwmGlobalMalloc(sizeof(header_client_state_t));
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
    return (api_result_t){0};
}

tunnel_t *destroyHeaderClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataHeaderClient(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
