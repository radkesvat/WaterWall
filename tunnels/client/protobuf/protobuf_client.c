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

} protobuf_client_state_t;

typedef struct protobuf_client_con_state_s
{
    buffer_stream_t *stream_buf;
    bool             first_sent;

} protobuf_client_con_state_t;

static void cleanup(protobuf_client_con_state_t *cstate)
{
    destroyBufferStream(cstate->stream_buf);
    free(cstate);
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
            protobuf_client_con_state_t *cstate = malloc(sizeof(protobuf_client_con_state_t));
            cstate->first_sent                  = false;
            cstate->stream_buf                  = newBufferStream(getContextBufferPool(c));
            CSTATE_MUT(c)                       = cstate;
        }
        else if (c->fin)
        {
            protobuf_client_con_state_t *cstate = CSTATE(c);
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
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
        bufferStreamPush(cstate->stream_buf, c->payload);
        c->payload = NULL;

        while (true)
        {
            if (bufferStreamLen(bstream) < 2)
            {
                destroyContext(c);
                return;
            }
            unsigned int  read_len = (bufferStreamLen(bstream) >= 4 ? 4 : 2);
            unsigned char uleb_encoded_buf[4];
            bufferStreamViewBytesAt(bstream, 1, uleb_encoded_buf, read_len);
            // if (uleb_encoded_buf[0] != '\n')
            // {
            //     LOGE("ProtoBufClient: rejected, invalid data");
            //     goto disconnect;
            // }

            size_t data_len     = 0;
            size_t bytes_passed = readUleb128ToUint64(uleb_encoded_buf, uleb_encoded_buf + read_len, &data_len);
            if (data_len == 0)
            {
                if (uleb_encoded_buf[0] == 0x0)
                {
                    LOGE("ProtoBufClient: rejected, invalid data");
                    goto disconnect;
                }

                // keep waiting for more data to come
                destroyContext(c);
                return;
            }
            if (data_len > kMaxPacketSize)
            {
                LOGE("ProtoBufClient: rejected, size too large %zu (%zu passed %lu left)", data_len, bytes_passed,
                     bufferStreamLen(bstream));
                goto disconnect;
            }
            if (! (bufferStreamLen(bstream) >= 1 + bytes_passed + data_len))
            {
                destroyContext(c);
                return;
            }
            context_t *downstream_ctx = newContextFrom(c);
            downstream_ctx->payload   = bufferStreamRead(cstate->stream_buf, 1 + bytes_passed + data_len);
            shiftr(downstream_ctx->payload, 1 + bytes_passed);
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
            cleanup(cstate);
            CSTATE_MUT(c) = NULL;
        }
        self->dw->downStream(self->dw, c);
    }
    return;
disconnect:;
    cleanup(cstate);
    CSTATE_MUT(c) = NULL;
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
    atomic_thread_fence(memory_order_release);
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
tunnel_metadata_t getMetadataProtoBufClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}