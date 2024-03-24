#include "bridge.h"
#include "loggers/network_logger.h"


#define MAX_PACKET_SIZE 65536

#define STATE(x) ((bridge_state_t *)((x)->state))
#define CSTATE(x) ((bridge_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct bridge_state_s
{

} bridge_state_t;

typedef struct bridge_con_state_s
{


} bridge_con_state_t;



static void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {

        // LOGD("upstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 200), rawBuf(c->payload));
        size_t blen = bufLen(c->payload);
        size_t calculated_bytes = size_uleb128(blen);
        shiftl(c->payload, calculated_bytes);
        write_uleb128(rawBuf(c->payload), blen);

        shiftl(c->payload, 1);
        writeUI8(c->payload, '\n');
    }
    else
    {
        if (c->init)
        {
            bridge_con_state_t *cstate = malloc(sizeof(bridge_con_state_t));
            cstate->wanted = 0;
            cstate->stream_buf = newBufferStream(buffer_pools[c->line->tid]);
            CSTATE_MUT(c) = cstate;
        }
        else if (c->fin)
        {
            bridge_con_state_t *cstate = CSTATE(c);
            destroyBufferStream(cstate->stream_buf);
            free(cstate);
            CSTATE_MUT(c) = NULL;
        }
    }

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        // LOGD("upstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 200), rawBuf(c->payload));

        bridge_con_state_t *cstate = CSTATE(c);
        if (cstate->wanted > 0)
        {
            bufferStreamPush(cstate->stream_buf, c->payload);
            c->payload = NULL;
            process(self, c);
            destroyContext(c);
            return;
        }
        else
        {

            shift_buffer_t *buf = c->payload;
            if (bufLen(buf) < 2)
            {
                DISCARD_CONTEXT(c);
                destroyContext(c);
                return;
            }

            shiftr(buf, 1); // first byte is \n (grpc byte array identifier? always \n? )
            size_t data_len = 0;
            size_t bytes_passed = read_uleb128_to_uint64(rawBuf(buf), rawBuf(buf) + bufLen(buf), &data_len);
            shiftr(buf, bytes_passed);
            if (data_len > MAX_PACKET_SIZE)
            {
                LOGE("ProtoBuf Client: a grpc chunk rejected, size too large");
                DISCARD_CONTEXT(c);
                destroyContext(c);
                return;
            }
            if (data_len != bufLen(buf))
            {
                cstate->wanted = data_len;
                bufferStreamPush(cstate->stream_buf, c->payload);
                c->payload = NULL;
                destroyContext(c);
                return;
            }
        }
    }
    else
    {
        if (c->fin)
        {
            bridge_con_state_t *cstate = CSTATE(c);
            destroyBufferStream(cstate->stream_buf);
            free(cstate);
            CSTATE_MUT(c) = NULL;
        }
    }
    self->dw->downStream(self->dw, c);
}

static void ProtoBufClientUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void ProtoBufClientPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void ProtoBufClientDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void ProtoBufClientPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newProtoBufClient(node_instance_context_t *instance_info)
{

    tunnel_t *t = newTunnel();

    t->upStream = &ProtoBufClientUpStream;
    t->packetUpStream = &ProtoBufClientPacketUpStream;
    t->downStream = &ProtoBufClientDownStream;
    t->packetDownStream = &ProtoBufClientPacketDownStream;
    return t;
}

api_result_t apiProtoBufClient(tunnel_t *self, char *msg)
{
    LOGE("protobuf-client API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyProtoBufClient(tunnel_t *self)
{
    LOGE("protobuf-client DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataProtoBufClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}