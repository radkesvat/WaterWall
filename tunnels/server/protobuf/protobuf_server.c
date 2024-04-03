#include "protobuf_server.h"
#include "loggers/network_logger.h"
/*
    we shall not use nanopb or any protobuf lib because they need atleast 1 memcopy
    i have read the byte array implemntation of the protoc and
    we do encoding/decoding right to the buffer
*/
#include "buffer_stream.h"
// #include <pb_encode.h>
// #include <pb_decode.h>
// #include "packet.pb.h"
#include "uleb128.h"

#define MAX_PACKET_SIZE 65535

#define STATE(x) ((protobuf_server_state_t *)((x)->state))
#define CSTATE(x) ((protobuf_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct protobuf_server_state_s
{

} protobuf_server_state_t;

typedef struct protobuf_server_con_state_s
{
    buffer_stream_t *stream_buf;
    size_t wanted;
    bool first_sent;

} protobuf_server_con_state_t;

static void cleanup(protobuf_server_con_state_t *cstate)
{
    destroyBufferStream(cstate->stream_buf);
    free(cstate);
}
static inline void upStream(tunnel_t *self, context_t *c);

static void process(tunnel_t *self, context_t *cin)
{
    protobuf_server_con_state_t *cstate = CSTATE(cin);
    buffer_stream_t *bstream = cstate->stream_buf;
    if (bufferStreamLen(bstream) < cstate->wanted || cstate->wanted <= 0)
        return;

    context_t *c = newContextFrom(cin);
    c->payload = bufferStreamRead(bstream, cstate->wanted);
    if (!cstate->first_sent)
    {
        cstate->first_sent = true;
        c->first = true;
    }
    self->up->upStream(self->up, c);
    cstate->wanted = 0;

    if (bufferStreamLen(bstream) > 0)
    {
        context_t *c_left = newContextFrom(cin);
        c_left->payload = bufferStreamRead(bstream, bufferStreamLen(bstream));
        self->upStream(self, c_left);
    }
}

static inline void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        protobuf_server_con_state_t *cstate = CSTATE(c);
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
                cleanup(cstate);
                CSTATE_MUT(c) = NULL;

                self->up->upStream(self->up, newFinContext(c->line));
                self->dw->downStream(self->dw, newFinContext(c->line));
                destroyContext(c);
                return;
            }

            shiftr(buf, 1); // first byte is \n (grpc byte array identifier? always \n? )
            size_t data_len = 0;
            size_t bytes_passed = read_uleb128_to_uint64(rawBuf(buf), rawBuf(buf) + bufLen(buf), &data_len);
            shiftr(buf, bytes_passed);
            if (data_len > MAX_PACKET_SIZE)
            {
                LOGE("ProtoBufServer: rejected, size too large %zu (%zu passed %d left)",data_len,bytes_passed,(int)(bufLen(buf)));
                DISCARD_CONTEXT(c);
                cleanup(cstate);
                CSTATE_MUT(c) = NULL;

                self->up->upStream(self->up, newFinContext(c->line));
                self->dw->downStream(self->dw, newFinContext(c->line));
                destroyContext(c);
                return;
            }
            if (data_len != bufLen(buf))
            {
                cstate->wanted = data_len;
                bufferStreamPush(cstate->stream_buf, c->payload);
                c->payload = NULL;
                if (data_len >= bufLen(buf))
                    process(self, c);
                destroyContext(c);
                return;
            }
        }
    }
    else
    {
        if (c->init)
        {
            protobuf_server_con_state_t *cstate = malloc(sizeof(protobuf_server_con_state_t));
            cstate->wanted = 0;
            cstate->first_sent = false;
            cstate->stream_buf = newBufferStream(buffer_pools[c->line->tid]);
            CSTATE_MUT(c) = cstate;
        }
        else if (c->fin)
        {
            cleanup(CSTATE(c));
            CSTATE_MUT(c) = NULL;
        }
    }
    if (c->first)
        CSTATE(c)->first_sent = true;

    self->up->upStream(self->up, c);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        size_t blen = bufLen(c->payload);
        size_t calculated_bytes = size_uleb128(blen);
        shiftl(c->payload, calculated_bytes);
        write_uleb128(rawBuf(c->payload), blen);

        shiftl(c->payload, 1);
        writeUI8(c->payload, '\n');
    }
    else
    {
        if (c->fin)
        {
            protobuf_server_con_state_t *cstate = CSTATE(c);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
        }
    }
    self->dw->downStream(self->dw, c);
}

static void ProtoBufServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void ProtoBufServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void ProtoBufServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void ProtoBufServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newProtoBufServer(node_instance_context_t *instance_info)
{

    tunnel_t *t = newTunnel();

    t->upStream = &ProtoBufServerUpStream;
    t->packetUpStream = &ProtoBufServerPacketUpStream;
    t->downStream = &ProtoBufServerDownStream;
    t->packetDownStream = &ProtoBufServerPacketDownStream;
    atomic_thread_fence(memory_order_release);

    return t;
}

api_result_t apiProtoBufServer(tunnel_t *self, char *msg)
{
    LOGE("protobuf-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyProtoBufServer(tunnel_t *self)
{
    LOGE("protobuf-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
tunnel_metadata_t getMetadataProtoBufServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}