#include "header_client.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"
#include "loggers/network_logger.h"

#define MAX_PACKET_SIZE 65535

#define STATE(x) ((header_client_state_t *)((x)->state))
#define CSTATE(x) ((header_client_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

enum header_dynamic_value_status
{
    hdvs_empty = 0x0,
    hdvs_constant,
    hdvs_source_port,
};

typedef struct header_client_state_s
{
    dynamic_value_t data;

} header_client_state_t;

typedef struct header_client_con_state_s
{

} header_client_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    header_client_state_t *state = STATE(self);

    if (c->payload != NULL && c->first)
    {

        switch ((enum header_dynamic_value_status)state->data.status)
        {
        case hdvs_source_port:
            shiftl(c->payload, sizeof(uint16_t));
            writeUI16(c->payload, sockaddr_port(&(c->line->src_ctx.addr)));
            break;

        default:
            break;
        }
    }

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    self->dw->downStream(self->dw, c);
}

static void headerClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void headerClientPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void headerClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void headerClientPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newHeaderClient(node_instance_context_t *instance_info)
{

    header_client_state_t *state = malloc(sizeof(header_client_state_t));
    memset(state, 0, sizeof(header_client_state_t));
    const cJSON *settings = instance_info->node_settings_json;
    state->data = parseDynamicNumericValueFromJsonObject(settings, "data", 1,
                                                         "src_context->port");
    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &headerClientUpStream;
    t->packetUpStream = &headerClientPacketUpStream;
    t->downStream = &headerClientDownStream;
    t->packetDownStream = &headerClientPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiHeaderClient(tunnel_t *self, char *msg)
{
    (void)(self); (void)(msg); return (api_result_t){0}; // TODO
}

tunnel_t *destroyHeaderClient(tunnel_t *self)
{
    return NULL;
}
tunnel_metadata_t getMetadataHeaderClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}