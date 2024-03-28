#include "header_server.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"
#include "loggers/network_logger.h"

#define MAX_PACKET_SIZE 65536

#define STATE(x) ((header_server_state_t *)((x)->state))
#define CSTATE(x) ((header_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

enum header_dynamic_value_status
{
    hdvs_empty = 0x0,
    hdvs_constant,
    hdvs_dest_port,
};

typedef struct header_server_state_s
{
    dynamic_value_t data;

} header_server_state_t;

typedef struct header_server_con_state_s
{

} header_server_con_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
    header_server_state_t *state = STATE(self);

    if (c->payload != NULL && c->first)
    {

        shift_buffer_t *buf = c->payload;
        if (bufLen(buf) < 2)
        {
            DISCARD_CONTEXT(c);
            self->up->upStream(self->up, newFinContext(c->line));
            self->dw->downStream(self->dw, newFinContext(c->line));
            destroyContext(c);
            return;
        }

        uint16_t port = 0;
        switch ((enum header_dynamic_value_status)state->data.status)
        {
        case hdvs_dest_port:

            readUI16(buf, &port);
            sockaddr_set_port(&(c->line->dest_ctx.addr), port);
            shiftr(c->payload, sizeof(uint16_t));
            break;

        default:
            (void)(0);
            break;
        }
    }

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    self->dw->downStream(self->dw, c);
}

static void HeaderServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void HeaderServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void HeaderServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void HeaderServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newHeaderServer(node_instance_context_t *instance_info)
{

    header_server_state_t *state = malloc(sizeof(header_server_state_t));
    memset(state, 0, sizeof(header_server_state_t));
    const cJSON *settings = instance_info->node_settings_json;
    state->data = parseDynamicNumericValueFromJsonObject(settings, "override", 1,
                                                         "dest_context->port");
    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &HeaderServerUpStream;
    t->packetUpStream = &HeaderServerPacketUpStream;
    t->downStream = &HeaderServerDownStream;
    t->packetDownStream = &HeaderServerPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiHeaderServer(tunnel_t *self, char *msg)
{
    LOGE("protobuf-client API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyHeaderServer(tunnel_t *self)
{
    LOGE("protobuf-client DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataHeaderServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}