#include "trojan_socks_server.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"
#include "loggers/network_logger.h"
#include "utils/stringutils.h"
#include "utils/userutils.h"


#define CRLF_LEN 2

enum trojan_cmd
{
    kTrojancmdConnect      = 0X1,
    kTrojancmdUdpAssociate = 0X3,
};
enum trojan_atyp
{
    kTrojanatypIpV4       = 0X1,
    kTrojanatypDomainname = 0X3,
    kTrojanatypIpV6       = 0X4,
};

typedef struct trojan_socks_server_state_s
{

} trojan_socks_server_state_t;

typedef struct trojan_socks_server_con_state_s
{
    bool init_sent;
    bool first_sent;
    bool is_udp_forward;

    buffer_stream_t *udp_buf;

} trojan_socks_server_con_state_t;

static void makeUdpPacketAddress(context_t *c)
{
    uint16_t packet_len = bufLen(c->payload);
    assert(packet_len < 8192);

    shiftl(c->payload, CRLF_LEN);
    writeRaw(c->payload, (unsigned char *) "\r\n", 2);

    packet_len = (packet_len << 8) | (packet_len >> 8);
    shiftl(c->payload, 2); // LEN
    writeUI16(c->payload, packet_len);

    uint16_t port = sockaddr_port(&(c->line->dest_ctx.addr));
    port          = (port << 8) | (port >> 8);
    shiftl(c->payload, 2); // port
    writeUI16(c->payload, port);

    switch (c->line->dest_ctx.atype)
    {
    case kSatIPV6:
        shiftl(c->payload, 16);
        writeRaw(c->payload, &(c->line->dest_ctx.addr.sin6.sin6_addr), 16);
        shiftl(c->payload, 1);
        writeUI8(c->payload, kSatIPV6);

    case kSatIPV4:
    default:
        shiftl(c->payload, 4);
        writeRaw(c->payload, &(c->line->dest_ctx.addr.sin.sin_addr), 4);
        shiftl(c->payload, 1);
        writeUI8(c->payload, kSatIPV4);
        break;
    }
}

static bool parseAddress(context_t *c)
{
    if (bufLen(c->payload) < 2)
    {
        return false;
    }
    socket_context_t *dest_context = &(c->line->dest_ctx);
    enum trojan_cmd   command      = ((unsigned char *) rawBuf(c->payload))[0];
    enum trojan_atyp  address_type = ((unsigned char *) rawBuf(c->payload))[1];
    dest_context->acmd             = (enum socket_address_cmd)(command);
    dest_context->atype            = (enum socket_address_type)(address_type);
    shiftr(c->payload, 2);

    switch (command)
    {
    case kTrojancmdConnect:
        dest_context->protocol = IPPROTO_TCP;
        switch (address_type)
        {
        case kTrojanatypIpV4:
            if (bufLen(c->payload) < 4)
            {
                return false;
            }
            dest_context->addr.sa.sa_family = AF_INET;
            memcpy(&(dest_context->addr.sin.sin_addr), rawBuf(c->payload), 4);
            shiftr(c->payload, 4);
            LOGD("TrojanSocksServer: tcp connect ipv4");
            break;
        case kTrojanatypDomainname:
            if (bufLen(c->payload) < 1)
            {
                return false;
            }
            uint8_t addr_len = ((uint8_t *) rawBuf(c->payload))[0];
            shiftr(c->payload, 1);
            if (bufLen(c->payload) < addr_len)
            {
                return false;
            }
            LOGD("TrojanSocksServer: tcp connect domain %.*s", addr_len, rawBuf(c->payload));
            setSocketContextDomain(dest_context, rawBuf(c->payload), addr_len);
            shiftr(c->payload, addr_len);
            break;
        case kTrojanatypIpV6:
            if (bufLen(c->payload) < 16)
            {
                return false;
            }
            dest_context->addr.sa.sa_family = AF_INET6;
            memcpy(&(dest_context->addr.sin.sin_addr), rawBuf(c->payload), 16);
            shiftr(c->payload, 16);
            LOGD("TrojanSocksServer: tcp connect ipv6");
            break;

        default:
            LOGD("TrojanSocksServer: address_type was incorrect (%02X) ", (unsigned int) (address_type));
            return false;
            break;
        }
        break;
    case kTrojancmdUdpAssociate:
        dest_context->protocol = IPPROTO_UDP;
        switch (address_type)
        {

        case kTrojanatypIpV4:
            if (bufLen(c->payload) < 4)
            {
                return false;
            }
            shiftr(c->payload, 4);
            dest_context->addr.sa.sa_family = AF_INET;
            // LOGD("TrojanSocksServer: udp associate ipv4");

            break;
        case kTrojanatypDomainname:
            // LOGD("TrojanSocksServer: udp domain ");

            dest_context->addr.sa.sa_family = AF_INET;

            if (bufLen(c->payload) < 1)
            {
                return false;
            }
            uint8_t addr_len = ((uint8_t *) rawBuf(c->payload))[0];
            shiftr(c->payload, 1);
            if (bufLen(c->payload) < addr_len)
            {
                return false;
            }
            shiftr(c->payload, addr_len);

            break;
        case kTrojanatypIpV6:
            if (bufLen(c->payload) < 16)
            {
                return false;
            }
            shiftr(c->payload, 16);
            // LOGD("TrojanSocksServer: connect ipv6");

            break;
        default:
            LOGD("TrojanSocksServer: address_type was incorrect (%02X) ", (unsigned int) (address_type));
            return false;
            break;
        }
        break;
    default:
        LOGE("TrojanSocksServer: command was incorrect (%02X) ", (unsigned int) (command));
        return false;
        break;
    }
    // port(2) + crlf(2)
    if (bufLen(c->payload) < 4)
    {
        return false;
    }
    uint16_t port = 0;
    memcpy(&port, rawBuf(c->payload), 2);
    port = (port << 8) | (port >> 8);
    sockaddr_set_port(&(dest_context->addr), port);
    shiftr(c->payload, 2 + CRLF_LEN);
    return true;
}

static bool processUdp(tunnel_t *self, trojan_socks_server_con_state_t *cstate, line_t *line, hio_t *src_io)
{
    buffer_stream_t *bstream = cstate->udp_buf;
    if (bufferStreamLen(bstream) <= 0)
    {
        return true;
    }

    uint8_t  atype       = bufferStreamViewByteAt(bstream, 0);
    uint16_t packet_size = 0;
    uint16_t full_len    = 0;
    uint8_t  domain_len  = 0;
    switch (atype)
    {
    case kTrojanatypIpV4:
        // address_type | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //       1      |    4     |   2      |   2    |    2

        if (bufferStreamLen(bstream) < 1 + 4 + 2 + 2 + 2)
        {
            return true;
        }

        {
            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 1 + 4 + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 1 + 4 + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }
        full_len = 1 + 4 + 2 + 2 + 2 + packet_size;

        break;
    case kTrojanatypDomainname:
        // address_type | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //      1       | x(1) + x |   2      |   2    |    2
        if (bufferStreamLen(bstream) < 1 + 1 + 2 + 2 + 2)
        {
            return true;
        }
        domain_len = bufferStreamViewByteAt(bstream, 1);

        if (bufferStreamLen(bstream) < 1 + 1 + domain_len + 2 + 2 + 2)
        {
            return true;
        }
        {
            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 1 + 1 + domain_len + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 1 + 1 + domain_len + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }
        full_len = 1 + 1 + domain_len + 2 + 2 + 2 + packet_size;

        break;
    case kTrojanatypIpV6:
        // address_type | DST.ADDR | DST.PORT | Length |  CRLF   | Payload
        //  1   |   16     |   2      |   2    |    2

        if (bufferStreamLen(bstream) < 1 + 16 + 2 + 2 + 2)
        {
            return true;
        }
        {

            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 1 + 16 + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 1 + 16 + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }

        full_len = 1 + 16 + 2 + 2 + 2 + packet_size;

        break;

    default:
        return false;
        break;
    }
    if (bufferStreamLen(bstream) < full_len)
    {
        return true;
    }

    context_t *       c             = newContext(line);
    socket_context_t *dest_context  = &(c->line->dest_ctx);
    c->src_io                       = src_io;
    c->payload                      = bufferStreamRead(bstream, full_len);
    dest_context->addr.sa.sa_family = AF_INET;

    shiftr(c->payload, 1);

    switch (atype)
    {
    case kTrojanatypIpV4:
        dest_context->addr.sa.sa_family = AF_INET;
        dest_context->atype             = kSatIPV4;
        memcpy(&(dest_context->addr.sin.sin_addr), rawBuf(c->payload), 4);
        shiftr(c->payload, 4);
        if (! cstate->first_sent)
        {
            LOGD("TrojanSocksServer: udp ipv4");
        }

        break;
    case kTrojanatypDomainname:
        dest_context->atype = kSatDomainName;
        // size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
        shiftr(c->payload, 1);
        if (dest_context->domain == NULL)
        {
            dest_context->domain = malloc(260);

            if (! cstate->first_sent) // print once per connection
            {
                LOGD("TrojanSocksServer: udp domain %.*s", domain_len, rawBuf(c->payload));
            }

            memcpy(dest_context->domain, rawBuf(c->payload), domain_len);
            dest_context->domain[domain_len] = 0;
        }
        shiftr(c->payload, domain_len);

        break;
    case kTrojanatypIpV6:
        dest_context->atype             = kSatIPV6;
        dest_context->addr.sa.sa_family = AF_INET6;
        memcpy(&(dest_context->addr.sin.sin_addr), rawBuf(c->payload), 16);
        shiftr(c->payload, 16);
        if (! cstate->first_sent)
        {
            LOGD("TrojanSocksServer: udp ipv6");
        }
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
    sockaddr_set_port(&(dest_context->addr), port);
    shiftr(c->payload, 2);

    // len(2) + crlf(2)
    if (bufLen(c->payload) < 4)
    {
        return false;
    }
    // memcpy(&(c->packet_size), rawBuf(c->payload), 2);
    shiftr(c->payload, 2 + CRLF_LEN); //(2bytes) packet size already taken
    // c->packet_size = (c->packet_size << 8) | (c->packet_size >> 8);

    assert(bufLen(c->payload) == packet_size);
    if (! cstate->first_sent)
    {
        c->first           = true;
        cstate->first_sent = true;
    }
    // send init ctx
    if (! cstate->init_sent)
    {
        context_t *up_init_ctx = newContextFrom(c);
        up_init_ctx->init      = true;
        self->up->packetUpStream(self->up, up_init_ctx);
        if (! isAlive(c))
        {
            LOGW("TrojanSocksServer: next node instantly closed the init with fin");
            return true;
        }
        cstate->init_sent = true;
    }

    self->up->packetUpStream(self->up, c);

    // line is alvie because caller is holding a context, but still  fin could received
    // and state is gone
    if (line->chains_state[self->chain_index] == NULL)
    {
        return true;
    }
    return processUdp(self, cstate, line, src_io);
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {

        if (c->first)
        {
            if (parseAddress(c))
            {
                trojan_socks_server_con_state_t *cstate       = CSTATE(c);
                socket_context_t *               dest_context = &(c->line->dest_ctx);

                if (dest_context->protocol == IPPROTO_TCP)
                {
                    context_t *up_init_ctx = newContextFrom(c);
                    up_init_ctx->init      = true;
                    self->up->upStream(self->up, up_init_ctx);
                    if (! isAlive(c->line))
                    {
                        LOGW("TrojanSocksServer: next node instantly closed the init with fin");
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                    cstate->init_sent = true;
                }
                else if (dest_context->protocol == IPPROTO_UDP)
                {
                    // udp will not call init here since no dest_context addr is available right now
                    cstate->is_udp_forward = true;
                    // self->up->packetUpStream(self->up, up_init_ctx);
                }

                if (bufLen(c->payload) <= 0)
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                if (dest_context->protocol == IPPROTO_TCP)
                {
                    if (! cstate->first_sent)
                    {
                        c->first           = true;
                        cstate->first_sent = true;
                    }
                    self->up->upStream(self->up, c);
                    return;
                }
                if (dest_context->protocol == IPPROTO_UDP)
                {
                    bufferStreamPush(cstate->udp_buf, c->payload);
                    c->payload = NULL;

                    if (! processUdp(self, cstate, c->line, c->src_io))
                    {
                        LOGE("TrojanSocksServer: udp packet could not be parsed");

                        if (cstate->init_sent)
                        {
                            context_t *fin_up = newFinContext(c->line);

                            self->up->upStream(self->up, fin_up);
                        }

                        destroyBufferStream(cstate->udp_buf);
                        free(cstate);
                        CSTATE_MUT(c)     = NULL;
                        context_t *fin_dw = newFinContext(c->line);
                        destroyContext(c);
                        self->dw->downStream(self->dw, fin_dw);
                    }
                    else
                    {
                        destroyContext(c);
                    }
                }
                else
                {
                    LOGF("unreachable trojan-socket_server");
                    exit(1);
                }
            }
            else
            {
                trojan_socks_server_con_state_t *cstate = CSTATE(c);

                reuseContextBuffer(c);
                destroyBufferStream(cstate->udp_buf);
                free(cstate);
                CSTATE_MUT(c)    = NULL;
                context_t *reply = newFinContext(c->line);
                destroyContext(c);
                self->dw->downStream(self->dw, reply);
            }
        }
        else
        {
            trojan_socks_server_con_state_t *cstate = CSTATE(c);

            if (cstate->is_udp_forward)
            {
                bufferStreamPush(cstate->udp_buf, c->payload);
                c->payload = NULL;

                if (! processUdp(self, cstate, c->line, c->src_io))
                {
                    LOGE("TrojanSocksServer: udp packet could not be parsed");

                    {
                        context_t *fin_up = newContextFrom(c);
                        fin_up->fin       = true;
                        self->up->upStream(self->up, fin_up);
                    }

                    destroyBufferStream(cstate->udp_buf);
                    free(cstate);
                    CSTATE_MUT(c)     = NULL;
                    context_t *fin_dw = newContextFrom(c);
                    fin_dw->fin       = true;
                    destroyContext(c);
                    self->dw->downStream(self->dw, fin_dw);
                }
                else
                {
                    destroyContext(c);
                }
            }
            else
            {
                self->up->upStream(self->up, c);
            }
        }
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(trojan_socks_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(trojan_socks_server_con_state_t));
            trojan_socks_server_con_state_t *cstate = CSTATE(c);
            cstate->udp_buf                         = newBufferStream(buffer_pools[c->line->tid]);
            allocateDomainBuffer(&(c->line->dest_ctx));
            destroyContext(c);
        }
        else if (c->fin)
        {
            trojan_socks_server_con_state_t *cstate    = CSTATE(c);
            bool                             init_sent = cstate->init_sent;
            bool                             is_udp    = cstate->is_udp_forward;
            destroyBufferStream(cstate->udp_buf);
            free(cstate);
            CSTATE_MUT(c) = NULL;
            if (init_sent)
            {
                if (is_udp)
                {
                    self->up->packetUpStream(self->up, c);
                }
                else
                {
                    self->up->upStream(self->up, c);
                }
            }
            else
            {
                destroyContext(c);
            }
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    trojan_socks_server_con_state_t *cstate    = CSTATE(c);

    if (c->fin)
    {
        destroyBufferStream(cstate->udp_buf);
        free(cstate);
        CSTATE_MUT(c) = NULL;
        self->dw->downStream(self->dw, c);
        return;
    }
    if (cstate->is_udp_forward && c->payload != NULL)
    {
        makeUdpPacketAddress(c);
    }
    self->dw->downStream(self->dw, c);
}

static void trojanSocksServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void trojanSocksServerPacketUpStream(tunnel_t *self, context_t *c)
{
    if (c->init || c->first)
    {
        LOGE("TrojanSocksServer: trojan protocol is not meant to work on top of udp");
    }
    upStream(self, c);
}
static void trojanSocksServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void trojanSocksServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newTrojanSocksServer(node_instance_context_t *instance_info)
{
    (void) instance_info;
    trojan_socks_server_state_t *state = malloc(sizeof(trojan_socks_server_state_t));
    memset(state, 0, sizeof(trojan_socks_server_state_t));

    tunnel_t *t         = newTunnel();
    t->state            = state;
    t->upStream         = &trojanSocksServerUpStream;
    t->packetUpStream   = &trojanSocksServerPacketUpStream;
    t->downStream       = &trojanSocksServerDownStream;
    t->packetDownStream = &trojanSocksServerPacketDownStream;
    atomic_thread_fence(memory_order_release);
    return t;
}
api_result_t apiTrojanSocksServer(tunnel_t *self, const char *msg)
{
    (void) self;
    (void) msg;
    (void)(self); (void)(msg); return (api_result_t){0}; // TODO(root):
}

tunnel_t *destroyTrojanSocksServer(tunnel_t *self)
{
    (void) self;
    return NULL;
}

tunnel_metadata_t getMetadataTrojanSocksServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
