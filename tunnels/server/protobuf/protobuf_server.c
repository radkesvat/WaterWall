#include <stdio.h>

/*
    we shall not use nanopb or any protobuf lib because they need atleast 1 memcopy
    i have read the byte array impleemntation of the protoculbuffers and
    we do encoding/decoding right to the buffer
*/
#include "buffer_stream.h"
// #include <pb_encode.h>
// #include <pb_decode.h>
// #include "packet.pb.h"
#include "uleb128.h"

#define STATE(x) ((protobuf_server_state_t *)((x)->state))
#define CSTATE(x) ((protobuf_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

static inline size_t min(size_t x, size_t y) { return (((x) < (y)) ? (x) : (y)); }

typedef struct protobuf_server_state_s
{

} protobuf_server_state_t;

typedef struct protobuf_server_con_state_s
{
    buffer_stream_t *stream_buf;
    size_t wanted;

} protobuf_server_con_state_t;

static void process(tunnel_t *self, context_t carrying)
{
    assert(cstate->wanted > 0);
    buffer_stream_t *bstream = cstate->stream_buf;
    if (bufferStreamLen(bstream) < cstate->wanted)
        return ;


        context_t *c = newContext(carrying->line);
    c->src_io = 

    if (bufferStreamLen(bstream) == cstate->wanted)
    {
        
    c->payload = bufferStreamRead(bstream, full_len);



    }
    else
    {
    }

    uint8_t atype = bufferStreamReadByteAt(bstream, 0);
    uint16_t packet_size = 0;
    uint16_t full_len = 0;
    uint8_t domain_len = 0;
    switch (atype)
    {
    case TROJANATYP_IPV4:
        // ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //  1   |    4     |   2      |   2    |    2

        if (bufferStreamLen(bstream) < 1 + 4 + 2 + 2 + 2)
            return true;

        {
            uint8_t packet_size_H = bufferStreamReadByteAt(bstream, 1 + 4 + 2);
            uint8_t packet_size_L = bufferStreamReadByteAt(bstream, 1 + 4 + 2 + 1);
            packet_size = (packet_size_H << 8) | packet_size_L;
            if (packet_size > 8192)
                return false;
        }
        full_len = 1 + 4 + 2 + 2 + 2 + packet_size;

        break;
    case TROJANATYP_DOMAINNAME:
        // ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //  1   | x(1) + x |   2      |   2    |    2
        if (bufferStreamLen(bstream) < 1 + 1 + 2 + 2 + 2)
            return true;
        domain_len = bufferStreamReadByteAt(bstream, 1);

        if (bufferStreamLen(bstream) < 1 + 1 + domain_len + 2 + 2 + 2)
            return true;
        {
            uint8_t packet_size_H = bufferStreamReadByteAt(bstream, 1 + 1 + domain_len + 2);
            uint8_t packet_size_L = bufferStreamReadByteAt(bstream, 1 + 1 + domain_len + 2 + 1);
            packet_size = (packet_size_H << 8) | packet_size_L;
            if (packet_size > 8192)
                return false;
        }
        full_len = 1 + 1 + domain_len + 2 + 2 + 2 + packet_size;

        break;
    case TROJANATYP_IPV6:
        // ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //  1   |   16     |   2      |   2    |    2

        if (bufferStreamLen(bstream) < 1 + 16 + 2 + 2 + 2)
            return true;
        {

            uint8_t packet_size_H = bufferStreamReadByteAt(bstream, 1 + 16 + 2);
            uint8_t packet_size_L = bufferStreamReadByteAt(bstream, 1 + 16 + 2 + 1);
            packet_size = (packet_size_H << 8) | packet_size_L;
            if (packet_size > 8192)
                return false;
        }

        full_len = 1 + 16 + 2 + 2 + 2 + packet_size;

        break;

    default:
        return false;
        break;
    }
    if (bufferStreamLen(bstream) < full_len)
        return true;

    context_t *c = newContext(line);
    socket_context_t *dest = &(c->dest_ctx);
    c->src_io = src_io;
    c->payload = bufferStreamRead(bstream, full_len);
    dest->addr.sa.sa_family = AF_INET;

    shiftr(c->payload, 1);

    switch (atype)
    {
    case TROJANATYP_IPV4:
        dest->addr.sa.sa_family = AF_INET;
        dest->atype = SAT_IPV4;
        memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 4);
        shiftr(c->payload, 4);
        if (!cstate->first_sent)
            LOGD("TrojanSocksServer: udp ipv4");

        break;
    case TROJANATYP_DOMAINNAME:
        dest->atype = SAT_DOMAINNAME;
        // size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
        shiftr(c->payload, 1);
        dest->domain = malloc(260);

        if (!cstate->first_sent) // print once per connection
            LOGD("TrojanSocksServer: udp domain %.*s", domain_len, rawBuf(c->payload));

        memcpy(dest->domain, rawBuf(c->payload), domain_len);
        dest->domain[domain_len] = 0;
        shiftr(c->payload, domain_len);

        break;
    case TROJANATYP_IPV6:
        dest->atype = SAT_IPV6;
        dest->addr.sa.sa_family = AF_INET6;
        memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 16);
        shiftr(c->payload, 16);
        if (!cstate->first_sent)
            LOGD("TrojanSocksServer: udp ipv6");
        break;

    default:
        return false;
        break;
    }

    // port(2)
    if (bufLen(c->payload) < 2)
    {
        return false;
    }
    uint16_t port = 0;
    memcpy(&port, rawBuf(c->payload), 2);
    port = (port << 8) | (port >> 8);
    sockaddr_set_port(&(dest->addr), port);
    shiftr(c->payload, 2);

    // len(2) + crlf(2)
    if (bufLen(c->payload) < 4)
    {
        return false;
    }
    memcpy(&(c->packet_size), rawBuf(c->payload), 2);
    shiftr(c->payload, 2 + CRLF_LEN);
    c->packet_size = (c->packet_size << 8) | (c->packet_size >> 8);
    assert(bufLen(c->payload) == c->packet_size);
    if (!cstate->first_sent)
    {
        c->first = true;
        cstate->first_sent = true;
    }
    // send init ctx
    if (!cstate->init_sent)
    {

        context_t *up_init_ctx = newContextFrom(c);
        moveDestCtx(up_init_ctx, c);
        up_init_ctx->init = true;
        self->up->packetUpStream(self->up, up_init_ctx);
        if (!ISALIVE(c))
        {
            LOGW("TrojanSocksServer: next node instantly closed the init with fin");
            return false;
        }
        cstate->init_sent = true;
    }

    self->up->packetUpStream(self->up, c);

    return processUdp(self, cstate, line, src_io);
}

static inline void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        // LOGD("upstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 200), rawBuf(c->payload));

        trojan_socks_server_con_state_t *cstate = CSTATE(c);
        if (c->wanted > 0)
        {
            bufferStreamPush(cstate->stream_buf, c->payload);
            c->payload = NULL;
            process(self, cstate, c->line);
            destroyContext(c);
        }
        else
        {
            shift_buffer_t *buf = c->payload;
            shiftr(buf, 1); // first byte is \n (grpc byte array identifier? always \n? )
            size_t data_len = 0;
            size_t bytes_passed = read_uleb128_to_uint64(rawBuf(buf), rawBuf(buf) + bufLen(buf), &data_len);
            shiftr(buf, bytes_passed);
            assert(data_len >= bufLen(buf));
            if (data_len > bufLen(buf))
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
        if (c->init)
        {
            trojan_socks_server_con_state_t *cstate = malloc(sizeof(protobuf_server_con_state_t));
            cstate->wanted = 0;
            cstate->stream_buf = newBufferStream(buffer_pools[c->line->tid]);
            CSTATE_MUT(c) = cstate;
        }
        else if (c->fin)
        {
            trojan_socks_server_con_state_t *cstate = CSTATE(c);
            destroyBufferStream(cstate->stream_buf);
            free(cstate);
            CSTATE_MUT(c) = NULL;
        }
    }

    self->up->upStream(self->up, reply);
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {

        // LOGD("upstream: %zu bytes [ %.*s ]", bufLen(c->payload), min(bufLen(c->payload), 200), rawBuf(c->payload));
        if (self->dw != NULL)
        {
            self->dw->downStream(self->dw, c);
        }
        else
        {

            // send back something
            {
                context_t *reply = newContextFrom(c);
                reply->payload = popBuffer(buffer_pools[c->line->tid]);
                sprintf(rawBuf(reply->payload), "%s", "salam");
                setLen(reply->payload, strlen("salam"));
                self->up->upStream(self->up, reply);
            }

            DISCARD_CONTEXT(c);
            destroyContext(c);
        }
    }
    else
    {
        if (c->fin)
        {
            trojan_socks_server_con_state_t *cstate = CSTATE(c);
            destroyBufferStream(cstate->stream_buf);
            free(cstate);
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