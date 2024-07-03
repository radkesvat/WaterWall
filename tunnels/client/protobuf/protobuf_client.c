#include "protobuf_client.h"
#include "basic_types.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "node.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "uleb128.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
/*
    we shall not use nanopb or any protobuf lib because they need atleast 1 memcopy
    i have read the byte array implemntation of the protoc and
    we do encoding/decoding right to the buffer
*/
enum
{
    kMaxPacketSize = (65536 * 1)
};

typedef struct protobuf_client_state_s
{
    void *_;
} protobuf_client_state_t;

typedef struct protobuf_client_con_state_s
{
    buffer_stream_t *stream_buf;
    bool             first_sent;

} protobuf_client_con_state_t;

static void cleanup(protobuf_client_con_state_t *cstate)
{
    destroyBufferStream(cstate->stream_buf);
    wwmGlobalFree(cstate);
}

static void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {
        size_t blen             = bufLen(c->payload);
        size_t calculated_bytes = sizeUleb128(blen);
        shiftl(c->payload, calculated_bytes + 1);
        writeUleb128(rawBufMut(c->payload) + 1, blen);
        writeUI8(c->payload, '\n');
    }
    else
    {
        if (c->init)
        {
            protobuf_client_con_state_t *cstate = wwmGlobalMalloc(sizeof(protobuf_client_con_state_t));
            *cstate                             = (protobuf_client_con_state_t){.first_sent = false,
                                                                                .stream_buf = newBufferStream(getContextBufferPool(c))};
            CSTATE_MUT(c)                       = cstate;
        }
        else if (c->fin)
        {
            protobuf_client_con_state_t *cstate = CSTATE(c);
            CSTATE_DROP(c);
            cleanup(cstate);
        }
    }
    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    protobuf_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        buffer_stream_t *bstream = cstate->stream_buf;
        bufferStreamPushContextPayload(bstream, c);

        while (true)
        {
            if (bufferStreamLen(bstream) < 2)
            {
                destroyContext(c);
                return;
            }
            shift_buffer_t *full_data    = bufferStreamFullRead(bstream);
            const uint8_t  *uleb_data    = &(((uint8_t *) rawBuf(full_data))[1]); // first byte is \n (protobuf)
            uint64_t        data_len     = 0;
            size_t          bytes_passed = readUleb128ToUint64(uleb_data, uleb_data + bufLen(full_data) - 1, &data_len);
            if (data_len == 0 || (bufLen(full_data) - (bytes_passed + 1)) < data_len)
            {
                bufferStreamPush(bstream, full_data);
                destroyContext(c);
                return;
            }

            if (data_len > kMaxPacketSize)
            {
                LOGE("ProtoBufServer: rejected, size too large");
                goto disconnect;
            }

            shiftr(full_data, 1 + bytes_passed);

            context_t *downstream_ctx = newContextFrom(c);
            downstream_ctx->payload   = popBuffer(getContextBufferPool(c));

            sliceBufferTo(downstream_ctx->payload, full_data, data_len);
            // upstream_ctx->payload   = shallowSliceBuffer();

            if (bufLen(full_data) > 0)
            {
                bufferStreamPush(bstream, full_data);
            }
            else
            {
                reuseBuffer(getContextBufferPool(c), full_data);
            }

            if (! cstate->first_sent)
            {
                downstream_ctx->first = true;
                cstate->first_sent    = true;
            }

            self->dw->downStream(self->dw, downstream_ctx);

            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }
    }
    else
    {
        if (c->fin)
        {
            CSTATE_DROP(c);
            cleanup(cstate);
        }
        self->dw->downStream(self->dw, c);
    }
    return;
disconnect:;
    CSTATE_DROP(c);
    cleanup(cstate);
    self->up->upStream(self->up, newFinContext(c->line));
    self->dw->downStream(self->dw, newFinContext(c->line));
    destroyContext(c);
}

tunnel_t *newProtoBufClient(node_instance_context_t *instance_info)
{
    (void) instance_info;
    tunnel_t *t   = newTunnel();
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiProtoBufClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyProtoBufClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}
tunnel_metadata_t getMetadataProtoBufClient(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
