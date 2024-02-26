#include "trojan_socks_server.h"
#include "loggers/dns_logger.h"
#include "loggers/network_logger.h"
#include "utils/userutils.h"
#include "utils/stringutils.h"
#include "buffer_stream.h"
#include "hv/hsocket.h"

#define STATE(x) ((trojan_socks_server_state_t *)((x)->state))
#define CSTATE(x) ((trojan_socks_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

#define CRLF_LEN 2

enum trojan_cmd
{
    TROJANCMD_CONNECT = 0X1,
    TROJANCMD_UDP_ASSOCIATE = 0X3,
};
enum trojan_atyp
{
    TROJANATYP_IPV4 = 0X1,
    TROJANATYP_DOMAINNAME = 0X3,
    TROJANATYP_IPV6 = 0X4,

};

typedef struct trojan_socks_server_state_s
{

} trojan_socks_server_state_t;

typedef struct trojan_socks_server_con_state_s
{
    bool init_sent;
    bool is_udp_forward;

    buffer_stream_t *udp_buf;

} trojan_socks_server_con_state_t;

static bool parseUdpPacketAddress(context_t *c)
{
    socket_context_t *dest = &(c->dest_ctx);
    dest->addr.sa.sa_family = AF_INET;

    if (bufLen(c->payload) < 1)
    {
        return false;
    }
    enum trojan_atyp atyp = (unsigned char)rawBuf(c->payload)[0];
    shiftr(c->payload, 1);
    switch (atyp)
    {
    case TROJANATYP_IPV4:
        if (bufLen(c->payload) < 4)
        {
            return false;
        }
        dest->addr.sa.sa_family = AF_INET;
        dest->atype = SAT_IPV4;
        memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 4);
        shiftr(c->payload, 4);
        LOGD("TrojanSocksServer: udp ipv4");
        break;
    case TROJANATYP_DOMAINNAME:
        if (bufLen(c->payload) < 1)
        {
            return false;
        }
        dest->atype = SAT_DOMAINNAME;
        size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
        shiftr(c->payload, 1);
        if (bufLen(c->payload) < addr_len || addr_len > 225)
        {
            return false;
        }

        LOGD("TrojanSocksServer: udp domain %.*s", addr_len, rawBuf(c->payload));
        if (dest->domain == NULL)
        {
            dest->domain = malloc(260);
        }

        memcpy(dest->domain, rawBuf(c->payload), addr_len);
        dest->domain[addr_len] = 0;
        shiftr(c->payload, addr_len);

        break;
    case TROJANATYP_IPV6:
        if (bufLen(c->payload) < 16)
        {
            return false;
        }
        dest->atype = SAT_IPV6;
        dest->addr.sa.sa_family = AF_INET6;
        memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 16);

        shiftr(c->payload, 16);
        LOGD("TrojanSocksServer: udp ipv6");

        break;

    default:
        LOGD("TrojanSocksServer: udp atyp was incorrect (%02X) ", (unsigned int)(atyp));
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

    if (c->packet_size > 8192)
        return false;

    size_t len = bufLen(c->payload);
    reserve(c->payload, c->packet_size);
    setLen(c->payload, len);

    if (len != c->packet_size)
    {
        int x = bufLen(c->payload);
        LOGW("oeuoeuo");
    }

    return true;
}
static void makeUdpPacketAddress(context_t *c)
{
    uint16_t plen = bufLen(c->payload);
    assert(plen < 8192);

    shiftl(c->payload, CRLF_LEN);
    writeRaw(c->payload, "\r\n", 2);

    plen = (plen << 8) | (plen >> 8);
    shiftl(c->payload, 2); // LEN
    writeUI16(c->payload, plen);

    uint16_t port = sockaddr_port(&(c->dest_ctx.addr));
    port = (port << 8) | (port >> 8);
    shiftl(c->payload, 2); // port
    writeUI16(c->payload, port);

    if (c->dest_ctx.atype == SAT_IPV6)
    {
        shiftl(c->payload, 16);
        memcpy(rawBuf(c->payload), &(c->dest_ctx.addr.sin6.sin6_addr), 16);
        shiftl(c->payload, 1);
        writeUI8(c->payload, SAT_IPV6);
    }
    else if (c->dest_ctx.atype == SAT_DOMAINNAME)
    {
        shiftl(c->payload, 16);
        memcpy(rawBuf(c->payload), &(c->dest_ctx.addr.sin6.sin6_addr), 16);
        shiftl(c->payload, 1);
        writeUI8(c->payload, SAT_IPV6);
    }
    else
    {
        shiftl(c->payload, 4);
        memcpy(rawBuf(c->payload), &(c->dest_ctx.addr.sin.sin_addr), 4);
        shiftl(c->payload, 1);
        writeUI8(c->payload, SAT_IPV4);
    }
}

static bool parseAddress(context_t *c)
{
    if (bufLen(c->payload) < 2)
    {
        return false;
    }
    socket_context_t *dest = &(c->dest_ctx);

    enum trojan_cmd cmd = (unsigned char)rawBuf(c->payload)[0];
    enum trojan_atyp atyp = (unsigned char)rawBuf(c->payload)[1];
    shiftr(c->payload, 2);

    dest->acmd = (enum socket_address_cmd)(cmd);
    dest->atype = (enum socket_address_type)(atyp);

    // the default, so set_port() works now even for domains
    dest->addr.sa.sa_family = AF_INET;

    switch (cmd)
    {
    case TROJANCMD_CONNECT:
        dest->protocol = IPPROTO_TCP;
        switch (atyp)
        {
        case TROJANATYP_IPV4:
            if (bufLen(c->payload) < 4)
            {
                return false;
            }
            dest->addr.sa.sa_family = AF_INET;
            memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 4);

            shiftr(c->payload, 4);

            LOGD("TrojanSocksServer: tcp connect ipv4");

            break;
        case TROJANATYP_DOMAINNAME:
            // TODO this should be done in router node or am i wrong?
            if (bufLen(c->payload) < 1)
            {
                return false;
            }
            size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
            shiftr(c->payload, 1);
            if (bufLen(c->payload) < addr_len || addr_len > 225)
            {
                return false;
            }

            LOGD("TrojanSocksServer: tcp connect domain %.*s", addr_len, rawBuf(c->payload));
            if (dest->domain == NULL)
            {
                dest->domain = malloc(260);
            }

            memcpy(dest->domain, rawBuf(c->payload), addr_len);
            dest->domain[addr_len] = 0;

            dest->resolved = false;

            shiftr(c->payload, addr_len);

            break;
        case TROJANATYP_IPV6:
            if (bufLen(c->payload) < 16)
            {
                return false;
            }
            dest->addr.sa.sa_family = AF_INET6;
            memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 16);

            shiftr(c->payload, 16);
            LOGD("TrojanSocksServer: tcp connect ipv6");

            /* code */
            break;

        default:
            LOGD("TrojanSocksServer: atyp was incorrect (%02X) ", (unsigned int)(atyp));
            return false;
            break;
        }
        break;
    case TROJANCMD_UDP_ASSOCIATE:
        dest->protocol = IPPROTO_UDP;
        switch (atyp)
        {

        case TROJANATYP_IPV4:
            if (bufLen(c->payload) < 4)
            {
                return false;
            }
            shiftr(c->payload, 4);
            dest->addr.sa.sa_family = AF_INET;
            // LOGD("TrojanSocksServer: udp associate ipv4");

            break;
        case TROJANATYP_DOMAINNAME:
            // LOGD("TrojanSocksServer: udp domain ");

            dest->addr.sa.sa_family = AF_INET;

            if (bufLen(c->payload) < 1)
            {
                return false;
            }
            size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
            shiftr(c->payload, 1);
            if (bufLen(c->payload) < addr_len || addr_len > 225)
            {
                return false;
            }
            shiftr(c->payload, addr_len);

            break;
        case TROJANATYP_IPV6:
            if (bufLen(c->payload) < 16)
            {
                return false;
            }
            shiftr(c->payload, 16);
            // LOGD("TrojanSocksServer: connect ipv6");

            break;
        default:
            LOGD("TrojanSocksServer: atyp was incorrect (%02X) ", (unsigned int)(atyp));
            return false;
            break;
        }
        break;
    default:
        LOGE("TrojanSocksServer: cmd was incorrect (%02X) ", (unsigned int)(cmd));
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
    sockaddr_set_port(&(dest->addr), port);
    shiftr(c->payload, 2 + CRLF_LEN);
    return true;
}

static bool processUdp(tunnel_t *self, trojan_socks_server_con_state_t *cstate, line_t *line, hio_t *src_io)
{
    buffer_stream_t *bstream = cstate->udp_buf;

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

    shift_buffer_t *payload = popBuffer(buffer_pools[line->tid]);
    reserve(payload, full_len);
    bool suc = bufferStreamRead(rawBuf(payload), full_len, bstream);
    assert(suc);
    setLen(payload, full_len);

    context_t *c = newContext(line);
    socket_context_t *dest = &(c->dest_ctx);
    c->src_io = src_io;
    c->payload = payload;
    dest->addr.sa.sa_family = AF_INET;

    shiftr(c->payload, 1);

    switch (atype)
    {
    case TROJANATYP_IPV4:
        dest->addr.sa.sa_family = AF_INET;
        dest->atype = SAT_IPV4;
        memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 4);
        shiftr(c->payload, 4);
        LOGD("TrojanSocksServer: udp ipv4");

        break;
    case TROJANATYP_DOMAINNAME:
        dest->atype = SAT_DOMAINNAME;
        // size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
        shiftr(c->payload, 1);
        dest->domain = malloc(260);

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
    self->up->packetUpStream(self->up, c);
    return true;
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {

        if (c->first)
        {
            if (parseAddress(c))
            {
                trojan_socks_server_con_state_t *cstate = CSTATE(c);
                socket_context_t *dest = &(c->dest_ctx);
                context_t *up_init_ctx = newContext(c->line);
                up_init_ctx->init = true;
                up_init_ctx->src_io = c->src_io;
                up_init_ctx->dest_ctx = c->dest_ctx;
                c->dest_ctx.domain = NULL; //  move
                if (dest->protocol == IPPROTO_TCP)
                {
                    self->up->upStream(self->up, up_init_ctx);
                }
                else if (dest->protocol == IPPROTO_UDP)
                {
                    cstate->is_udp_forward = true;
                    self->up->packetUpStream(self->up, up_init_ctx);
                }

                if (!ISALIVE(c))
                {
                    LOGW("TrojanSocksServer: next node instantly closed the init with fin");
                    DISCARD_CONTEXT(c);
                    destroyContext(c);

                    return;
                }
                cstate->init_sent = true;
                if (bufLen(c->payload) <= 0)
                {
                    DISCARD_CONTEXT(c);
                    destroyContext(c);
                    return;
                }
                if (dest->protocol == IPPROTO_TCP)
                {
                    self->up->upStream(self->up, c);
                    return;
                }
                else if (dest->protocol == IPPROTO_UDP)
                {
                    bufferStreamPush(cstate->udp_buf, c->payload);
                    c->payload = NULL;

                    if (!processUdp(self, cstate, c->line, c->src_io))
                    {
                        LOGE("TrojanSocksServer:  udp packet could not be parsed");

                        destroyBufferStream(cstate->udp_buf);
                        free(cstate);
                        CSTATE_MUT(c) = NULL;
                        context_t *reply = newContext(c->line);
                        reply->fin = true;
                        destroyContext(c);
                        self->dw->downStream(self->dw, reply);
                    }
                    else
                        destroyContext(c);
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

                DISCARD_CONTEXT(c);
                destroyBufferStream(cstate->udp_buf);
                free(cstate);
                CSTATE_MUT(c) = NULL;
                context_t *reply = newContext(c->line);
                reply->fin = true;
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

                if (!processUdp(self, cstate, c->line, c->src_io))
                {
                    LOGE("TrojanSocksServer:  udp packet could not be parsed");

                    destroyBufferStream(cstate->udp_buf);
                    free(cstate);
                    CSTATE_MUT(c) = NULL;
                    context_t *reply = newContext(c->line);
                    reply->fin = true;
                    destroyContext(c);
                    self->dw->downStream(self->dw, reply);
                }
                else
                    destroyContext(c);
            }
            else
                self->up->upStream(self->up, c);
        }
    }
    else
    {
        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(trojan_socks_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(trojan_socks_server_con_state_t));
            trojan_socks_server_con_state_t *cstate = CSTATE(c);
            cstate->udp_buf = newBufferStream(buffer_pools[c->line->tid]);
        }
        else if (c->fin)
        {
            trojan_socks_server_con_state_t *cstate = CSTATE(c);

            bool init_sent = cstate->init_sent;
            destroyBufferStream(cstate->udp_buf);
            free(cstate);
            CSTATE_MUT(c) = NULL;
            if (init_sent)
            {
                self->up->upStream(self->up, c);
            }
        }
    }
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    if (c->fin)
    {
        destroyBufferStream(CSTATE(c)->udp_buf);

        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
        self->dw->downStream(self->dw, c);
        return;
    }
    if (CSTATE(c)->is_udp_forward && c->payload != NULL)
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
    trojan_socks_server_state_t *state = malloc(sizeof(trojan_socks_server_state_t));
    memset(state, 0, sizeof(trojan_socks_server_state_t));

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &trojanSocksServerUpStream;
    t->packetUpStream = &trojanSocksServerPacketUpStream;
    t->downStream = &trojanSocksServerDownStream;
    t->packetDownStream = &trojanSocksServerPacketDownStream;
    atomic_thread_fence(memory_order_release);
    return t;
}
void apiTrojanSocksServer(tunnel_t *self, char *msg)
{
    LOGE("trojan-socks-server API NOT IMPLEMENTED"); // TODO
}

tunnel_t *destroyTrojanSocksServer(tunnel_t *self)
{
    LOGE("trojan-socks-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}
