#include "protobuf_server.h"

#include "buffer_pool.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "node.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "uleb128.h"
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
/*
    we shall not use nanopb or any protobuf lib because they need atleast 1 memcopy
    i have read the byte array implemntation of the protoc and
    we do encoding/decoding right to the buffer
*/
enum
{
    kMaxPacketSize    = (65536 * 1),
    kMaxRecvBeforeAck = (1 << 16),
    kMaxSendBeforeAck = (1 << 22)
};

typedef struct protobuf_server_state_s
{
    void *_;
} protobuf_server_state_t;

typedef struct protobuf_server_con_state_s
{
    buffer_stream_t *stream_buf;
    size_t           bytes_sent_nack;
    size_t           bytes_received_nack;

} protobuf_server_con_state_t;

static void cleanup(protobuf_server_con_state_t *cstate)
{
    destroyBufferStream(cstate->stream_buf);
    memoryFree(cstate);
}

static void upStream(tunnel_t *self, context_t *c)
{
    protobuf_server_con_state_t *cstate = CSTATE(c);

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
            sbuf_t *full_data = bufferStreamFullRead(bstream);
            uint8_t         flags;
            sbufReadUnAlignedUI8(full_data, &flags);
            sbufShiftRight(full_data, 1); // first byte is  (protobuf flag)

            const uint8_t *uleb_data    = sbufGetRawPtr(full_data);
            uint64_t       data_len     = 0;
            size_t         bytes_passed = readUleb128ToUint64(uleb_data, uleb_data + sbufGetBufLength(full_data), &data_len);

            if (data_len == 0 || (sbufGetBufLength(full_data) - (bytes_passed)) < data_len)
            {
                sbufShiftLeft(full_data, 1); // bring the data back to its original form

                bufferStreamPush(bstream, full_data);
                destroyContext(c);
                return;
            }

            if (data_len > kMaxPacketSize)
            {
                LOGE("ProtoBufServer: rejected, size too large");
                bufferpoolResuesBuffer(getContextBufferPool(c), full_data);
                goto disconnect;
            }

            sbufShiftRight(full_data, bytes_passed);

            if (flags == 0x1 && data_len == sizeof(uint32_t))
            {
                uint32_t consumed;
                memoryCopy(&consumed, sbufGetRawPtr(full_data), sizeof(uint32_t));
                consumed = ntohl(consumed);
                sbufShiftRight(full_data, sizeof(uint32_t));

                cstate->bytes_sent_nack -= consumed;

                if (cstate->bytes_sent_nack <= kMaxSendBeforeAck / 2)
                {
                    resumeLineUpSide(c->line);
                }

                if (sbufGetBufLength(full_data) > 0)
                {
                    bufferStreamPush(bstream, full_data);
                }
                else
                {
                    bufferpoolResuesBuffer(getContextBufferPool(c), full_data);
                }
            }
            else if (flags == '\n')
            {

                cstate->bytes_received_nack += (size_t) data_len;
                if (cstate->bytes_received_nack >= kMaxRecvBeforeAck)
                {

                    sbuf_t *flowctl_buf = bufferpoolGetLargeBuffer(getContextBufferPool(c));
                    sbufSetLength(flowctl_buf, sizeof(uint32_t));
                    sbufWriteUnAlignedUI32(flowctl_buf, htonl(cstate->bytes_received_nack));
                    cstate->bytes_received_nack = 0;

                    size_t blen             = sbufGetBufLength(flowctl_buf);
                    size_t calculated_bytes = sizeUleb128(blen);
                    sbufShiftLeft(flowctl_buf, calculated_bytes + 1);
                    writeUleb128(sbufGetMutablePtr(flowctl_buf) + 1, blen);
                    sbufWriteUnAlignedUI8(flowctl_buf, 0x1);

                    context_t *send_flow_ctx = newContextFrom(c);
                    send_flow_ctx->payload   = flowctl_buf;
                    self->dw->downStream(self->dw, send_flow_ctx);
                    if (! isAlive(c->line))
                    {
                        bufferpoolResuesBuffer(getContextBufferPool(c), full_data);
                        destroyContext(c);
                        return;
                    }
                }

                context_t *upstream_ctx = newContextFrom(c);
                upstream_ctx->payload   = bufferpoolGetLargeBuffer(getContextBufferPool(c));

                upstream_ctx->payload = sbufMoveTo(upstream_ctx->payload, full_data, data_len);

                if (sbufGetBufLength(full_data) > 0)
                {
                    bufferStreamPush(bstream, full_data);
                }
                else
                {
                    bufferpoolResuesBuffer(getContextBufferPool(c), full_data);
                }
                self->up->upStream(self->up, upstream_ctx);

                if (! isAlive(c->line))
                {
                    destroyContext(c);
                    return;
                }
            }
            else
            {
                LOGE("ProtoBufServer: rejected, invalid flag");
                bufferpoolResuesBuffer(getContextBufferPool(c), full_data);

                goto disconnect;
            }
        }
    }
    else
    {
        if (c->init)
        {
            cstate        = memoryAllocate(sizeof(protobuf_server_con_state_t));
            *cstate       = (protobuf_server_con_state_t) {.stream_buf = newBufferStream(getContextBufferPool(c))};
            CSTATE_MUT(c) = cstate;
        }
        else if (c->fin)
        {
            cleanup(cstate);
            CSTATE_DROP(c);
        }
        self->up->upStream(self->up, c);
    }

    return;
disconnect:
    cleanup(cstate);
    CSTATE_DROP(c);
    self->up->upStream(self->up, newFinContext(c->line));
    self->dw->downStream(self->dw, newFinContext(c->line));
    destroyContext(c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    protobuf_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        size_t blen             = sbufGetBufLength(c->payload);
        size_t calculated_bytes = sizeUleb128(blen);
        sbufShiftLeft(c->payload, calculated_bytes + 1);
        writeUleb128(sbufGetMutablePtr(c->payload) + 1, blen);
        sbufWriteUnAlignedUI8(c->payload, '\n');
        cstate->bytes_sent_nack += blen;
        if (cstate->bytes_sent_nack > kMaxSendBeforeAck)
        {
            pauseLineUpSide(c->line);
        }
    }
    else
    {
        if (c->fin)
        {
            cleanup(cstate);
            CSTATE_DROP(c);
        }
    }
    self->dw->downStream(self->dw, c);
}

tunnel_t *newProtoBufServer(node_instance_context_t *instance_info)
{

    (void) instance_info;
    tunnel_t *t   = tunnelCreate();
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiProtoBufServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyProtoBufServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataProtoBufServer(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
