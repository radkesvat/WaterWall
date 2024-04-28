#include "socks5_server.h"
#include "buffer_stream.h"
#include "utils/sockutils.h"
#include "loggers/network_logger.h"

#define SOCKS5_VERSION ((uint8_t) 5)

#define SOCKS5_AUTH_VERSION ((uint8_t) 1)
#define SOCKS5_AUTH_SUCCESS ((uint8_t) 0)
#define SOCKS5_AUTH_FAILURE ((uint8_t) 1)

typedef enum
{
    kNoAuth       = 0,
    kGssApiAuth   = 1,
    kUserPassAuth = 2,
} socks5_authMethod;

typedef enum
{
    kConnectCommand   = 1,
    kBindCommand      = 2,
    kAssociateCommand = 3,
} socks5_command;

typedef enum
{
    kIPv4Addr = 1,
    kFqdnAddr = 3,
    kIPv6Addr = 4,
} socks5_addr_type;

typedef enum
{
    kSuccessReply         = 0,
    kServerFailure        = 1,
    kRuleFailure          = 2,
    kNetworkUnreachable   = 3,
    kHostUnreachable      = 4,
    kConnectRefused       = 5,
    kTtlExpired           = 6,
    kCommandNotSupported  = 7,
    kAddrTypeNotSupported = 8,
} socks5_reply_code;

typedef enum
{
    kSBegin,
    kSAuthMethodsCount,
    kSAuthMethods,
    kSAuthUsernameLen,
    kSAuthUsername,
    kSAuthPasswordLen,
    kSAuthPassword,
    kSRequest,
    kSDstAddrType,
    kSDstAddrLen,
    kSDstAddr,
    kSDstPort,
    kSUpstream,
    kSEnd,
} socks5_state_e;

typedef struct socks5_server_state_s
{

} socks5_server_state_t;

typedef struct socks5_server_con_state_s
{
    bool             authenticated;
    bool             init_sent;
    bool             first_sent;
    socks5_state_e   state;
    shift_buffer_t * waitbuf;
    buffer_stream_t *udp_buf;
    unsigned int     need;

} socks5_server_con_state_t;

static void cleanup(socks5_server_con_state_t *cstate, buffer_pool_t *reusepool)
{
    if (cstate->waitbuf)
    {
        reuseBuffer(reusepool, cstate->waitbuf);
    }
    if (cstate->udp_buf)
    {
        destroyBufferStream(cstate->udp_buf);
    }
}
static void encapsultaeUdpPacket(context_t *c)
{
    uint16_t packet_len = bufLen(c->payload);

    packet_len = (packet_len << 8) | (packet_len >> 8);
    shiftl(c->payload, 2); // LEN
    writeUI16(c->payload, packet_len);

    uint16_t port = sockaddr_port(&(c->line->dest_ctx.address));
    port          = (port << 8) | (port >> 8);
    shiftl(c->payload, 2); // port
    writeUI16(c->payload, port);

    switch (c->line->dest_ctx.address_type)
    {
    case kSatIPV6:
        shiftl(c->payload, 16);
        writeRaw(c->payload, &(c->line->dest_ctx.address.sin6.sin6_addr), 16);
        shiftl(c->payload, 1);
        writeUI8(c->payload, kIPv6Addr);

    case kSatIPV4:
    default:
        shiftl(c->payload, 4);
        writeRaw(c->payload, &(c->line->dest_ctx.address.sin.sin_addr), 4);
        shiftl(c->payload, 1);
        writeUI8(c->payload, kIPv4Addr);
        break;
    }
    shiftl(c->payload, 1);
    writeUI8(c->payload, 0x0);
    shiftl(c->payload, 2);
    writeUI16(c->payload, 0x0);
}

static bool processUdp(tunnel_t *self, socks5_server_con_state_t *cstate, line_t *line, hio_t *src_io)
{
    buffer_stream_t *bstream = cstate->udp_buf;
    if (bufferStreamLen(bstream) <= 3)
    {
        return true;
    }

    uint8_t  address_type = bufferStreamViewByteAt(bstream, 3);
    uint16_t packet_size  = 0;
    uint16_t full_len     = 0;
    uint8_t  domain_len   = 0;
    switch (address_type)
    {
    case kIPv4Addr:
        // RSV | address_type | DST.ADDR | DST.PORT | Length | Payload
        //  3  |       1      |    4     |   2      |   2

        if (bufferStreamLen(bstream) < 3 + 1 + 4 + 2 + 2)
        {
            return true;
        }

        {
            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 3 + 1 + 4 + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 3 + 1 + 4 + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }
        full_len = 3 + 1 + 4 + 2 + 2 + packet_size;

        break;
    case kFqdnAddr:
        // RSV |address_type | DST.ADDR | DST.PORT | Length  | Payload
        //  3  |     1       | x(1) + x |    2     |   2

        if (bufferStreamLen(bstream) < 1 + 1 + 2 + 2 + 2)
        {
            return true;
        }
        domain_len = bufferStreamViewByteAt(bstream, 3 + 1);

        if (bufferStreamLen(bstream) < 3 + 1 + 1 + domain_len + 2 + 2)
        {
            return true;
        }
        {
            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 3 + 1 + 1 + domain_len + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 3 + 1 + 1 + domain_len + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }
        full_len = 3 + 1 + 1 + domain_len + 2 + 2 + packet_size;

        break;
    case kIPv6Addr:
        // RSV |address_type | DST.ADDR | DST.PORT | Length |  Payload
        //  3  |     1       |    16    |   2      |   2    |

        if (bufferStreamLen(bstream) < 3 + 1 + 16 + 2 + 2)
        {
            return true;
        }
        {

            uint8_t packet_size_h = bufferStreamViewByteAt(bstream, 3 + 1 + 16 + 2);
            uint8_t packet_size_l = bufferStreamViewByteAt(bstream, 3 + 1 + 16 + 2 + 1);
            packet_size           = (packet_size_h << 8) | packet_size_l;
            if (packet_size > 8192)
            {
                return false;
            }
        }

        full_len = 3 + 1 + 16 + 2 + 2 + packet_size;

        break;

    default:
        return false;
        break;
    }
    if (bufferStreamLen(bstream) < full_len)
    {
        return true;
    }

    context_t *       c                = newContext(line);
    socket_context_t *dest_context     = &(c->line->dest_ctx);
    c->src_io                          = src_io;
    c->payload                         = bufferStreamRead(bstream, full_len);
    dest_context->address.sa.sa_family = AF_INET;

    shiftr(c->payload, 3 + 1);

    switch (address_type)
    {
    case kIPv4Addr:
        dest_context->address.sa.sa_family = AF_INET;
        dest_context->address_type         = kSatIPV4;
        memcpy(&(dest_context->address.sin.sin_addr), rawBuf(c->payload), 4);
        shiftr(c->payload, 4);
        if (! cstate->first_sent)
        {
            LOGD("Socks5Server: udp ipv4");
        }

        break;
    case kFqdnAddr:
        dest_context->address_type = kSatDomainName;
        // size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
        shiftr(c->payload, 1);
        if (! cstate->first_sent) // print once per connection
        {
            LOGD("Socks5Server: udp domain %.*s", domain_len, rawBuf(c->payload));
        }

        socketContextDomainSet(dest_context, rawBuf(c->payload), domain_len);
        shiftr(c->payload, domain_len);

        break;
    case kIPv6Addr:
        dest_context->address_type         = kSatIPV6;
        dest_context->address.sa.sa_family = AF_INET6;
        memcpy(&(dest_context->address.sin.sin_addr), rawBuf(c->payload), 16);
        shiftr(c->payload, 16);
        if (! cstate->first_sent)
        {
            LOGD("Socks5Server: udp ipv6");
        }
        break;

    default:
        reuseContextBuffer(c);
        destroyContext(c);
        return false;
        break;
    }

    // port(2)
    if (bufLen(c->payload) < 2)
    {
        return false;
    }
    memcpy(&(dest_context->address.sin.sin_port), rawBuf(c->payload), 2);
    shiftr(c->payload, 2);

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
        self->up->upStream(self->up, up_init_ctx);
        if (! isAlive(c->line))
        {
            LOGW("Socks5Server: next node instantly closed the init with fin");
            reuseContextBuffer(c);
            destroyContext(c);
            return true;
        }
        cstate->init_sent = true;
    }
    self->up->upStream(self->up, c);

    // line is alvie because caller is holding a context, but still  fin could received
    // and state is gone
    if (! isAlive(line))
    {
        return true;
    }
    return processUdp(self, cstate, line, src_io);
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    socks5_server_state_t *    state  = STATE(self);
    socks5_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->state == kSUpstream)
        {
            if (c->line->dest_ctx.address_protocol == kSapUdp)
            {
                bufferStreamPush(cstate->udp_buf, c->payload);
                c->payload = NULL;

                if (! processUdp(self, cstate, c->line, c->src_io))
                {
                    LOGE("Socks5Server: udp packet could not be parsed");
                    self->up->upStream(self->up, newFinContext(c->line));
                    goto disconnect;
                }
                else
                {
                    destroyContext(c);
                }
            }
            else if (c->line->dest_ctx.address_protocol == kSapTcp)
            {
                if (! cstate->first_sent)
                {
                    c->first = cstate->first_sent = true;
                }
                self->up->upStream(self->up, c);
            }

            return;
        }
        if (cstate->waitbuf)
        {
            c->payload      = appendBufferMerge(getContextBufferPool(c), cstate->waitbuf, c->payload);
            cstate->waitbuf = NULL;
        }
    parsebegin:;

        if (bufLen(c->payload) < cstate->need)
        {
            cstate->waitbuf = c->payload;
            c->payload      = NULL;
            destroyContext(c);
            return;
        }

        shift_buffer_t *bytes = c->payload;

        switch (cstate->state)
        {
        case kSBegin:
            cstate->state = kSAuthMethodsCount;
        case kSAuthMethodsCount: {
            assert(cstate->need == 2);
            uint8_t version = 0;
            readUI8(bytes, &version);
            shiftr(bytes, 1);
            uint8_t methodscount = 0;
            readUI8(bytes, &methodscount);
            shiftr(bytes, 1);
            if (version != SOCKS5_VERSION || methodscount == 0)
            {
                LOGE("Socks5Server: Unsupprted socks version: %d", (int) version);
                reuseContextBuffer(c);
                goto disconnect;
            }
            cstate->state = kSAuthMethods;
            cstate->need  = methodscount;
            goto parsebegin;
        }
        break;
        case kSAuthMethods: {
            // TODO(root): check auth methods
            uint8_t authmethod = kNoAuth;
            // send auth mothod
            shift_buffer_t *resp = popBuffer(getContextBufferPool(c));
            shiftl(resp, 1);
            writeUI8(resp, kNoAuth);
            shiftl(resp, 1);
            writeUI8(resp, SOCKS5_VERSION);
            shiftr(bytes, cstate->need); // we've read and choosed 1 method
            context_t *reply = newContextFrom(c);
            reply->payload   = resp;
            self->dw->downStream(self->dw, reply);
            if (! isAlive(c->line))
            {
                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }
            cstate->state = kSRequest;
            cstate->need  = 3; // kNoAuth
            goto parsebegin;
        }
        break;
        case kSAuthUsernameLen:
        case kSAuthUsername:
        case kSAuthPasswordLen:
        case kSAuthPassword:
            reuseContextBuffer(c);
            goto disconnect;
            break;
        case kSRequest: {
            assert(cstate->need == 3);

            uint8_t version = 0;
            readUI8(bytes, &version);
            shiftr(bytes, 1);

            uint8_t cmd = 0;
            readUI8(bytes, &cmd);
            shiftr(bytes, 1);

            if (version != SOCKS5_VERSION || cmd != kConnectCommand && cmd != kAssociateCommand)
            {
                LOGE("Socks5Server: Unsupprted command: %d", (int) cmd);
                reuseContextBuffer(c);
                goto disconnect;
            }
            switch (cmd)
            {
            case kConnectCommand:
                c->line->dest_ctx.address_protocol = kSapTcp;
                break;
            case kAssociateCommand:
                c->line->dest_ctx.address_protocol = kSapUdp;
                cstate->udp_buf                    = newBufferStream(getContextBufferPool(c));
                break;
            default:
                reuseContextBuffer(c);
                goto disconnect;
            }
            shiftr(bytes, 1); // socks5 reserved 0x0
            cstate->state = kSDstAddrType;
            cstate->need  = 1;
            goto parsebegin;
        }
        break;
        case kSDstAddrType: {
            assert(cstate->need == 1);
            uint8_t satyp = 0;
            readUI8(bytes, &satyp);
            shiftr(bytes, 1);

            switch ((socks5_addr_type) satyp)
            {
            case kIPv4Addr:
                c->line->dest_ctx.address_type = kSatIPV4;
                cstate->need                   = 4;
                cstate->state                  = kSDstAddr;
                goto parsebegin;
                break;
            case kFqdnAddr:
                c->line->dest_ctx.address_type = kSatDomainName;
                cstate->need                   = 1;
                cstate->state                  = kSDstAddrLen;
                goto parsebegin;
                break;
            case kIPv6Addr:
                c->line->dest_ctx.address_type = kSatIPV6;
                cstate->need                   = 16;
                cstate->state                  = kSDstAddr;
                goto parsebegin;
                break;
            default:
                reuseContextBuffer(c);
                goto disconnect;
            }
        }
        break;
        case kSDstAddrLen: {
            assert(cstate->need == 1);
            uint8_t addr_len = 0;
            readUI8(bytes, &addr_len);
            shiftr(bytes, 1);

            if (addr_len == 0)
            {
                LOGE("Socks5Server: incorrect domain length");
                reuseContextBuffer(c);
                goto disconnect;
                return;
            }
            cstate->state = kSDstAddr;
            cstate->need  = addr_len;
            goto parsebegin;
        }
        break;
        case kSDstAddr: {
            switch (c->line->dest_ctx.address_type)
            {

            case kSatIPV4:
                assert(cstate->need == 4);
                c->line->dest_ctx.address.sa.sa_family = AF_INET;
                memcpy(&c->line->dest_ctx.address.sin.sin_addr, rawBuf(bytes), 4);
                shiftr(bytes, 4);

                break;
            case kSatDomainName:
                socketContextDomainSet(&c->line->dest_ctx, rawBuf(bytes), cstate->need);
                c->line->dest_ctx.domain_resolved = false;
                shiftr(bytes, cstate->need);
                break;
            case kSatIPV6:
                assert(cstate->need == 16);
                c->line->dest_ctx.address.sa.sa_family = AF_INET6;
                memcpy(&c->line->dest_ctx.address.sin6.sin6_addr, rawBuf(bytes), 16);
                shiftr(bytes, 16);
                break;
            default:
                reuseContextBuffer(c);
                goto disconnect;
                break;
            }
            cstate->state = kSDstPort;
            cstate->need  = 2;
            goto parsebegin;
        }
        break;
        case kSDstPort: {
            assert(cstate->need == 2);
            memcpy(&(c->line->dest_ctx.address.sin.sin_port), rawBuf(bytes), 2);
            shiftr(bytes, 2);

            if (logger_will_write_level(getNetworkLogger(), LOG_LEVEL_INFO))
            {
                if (c->line->dest_ctx.address_type == kSatDomainName)
                {
                    char localaddrstr[SOCKADDR_STRLEN] = {0};
                    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
                    SOCKADDR_STR(&c->line->src_ctx.address, localaddrstr);
                    SOCKADDR_STR(&c->line->dest_ctx.address, peeraddrstr);
                    LOGI("Socks5Server: [%s] =>  %.*s [%s] (%s)", localaddrstr, c->line->dest_ctx.domain,
                         c->line->dest_ctx.domain_len, peeraddrstr,
                         c->line->dest_ctx.address_protocol == kSapTcp ? "Tcp" : "Udp");
                }
                else
                {
                    char localaddrstr[SOCKADDR_STRLEN] = {0};
                    char peeraddrstr[SOCKADDR_STRLEN]  = {0};
                    SOCKADDR_STR(&c->line->src_ctx.address, localaddrstr);
                    SOCKADDR_STR(&c->line->dest_ctx.address, peeraddrstr);
                    LOGI("Socks5Server: [%s] =>  [%s] (%s)", localaddrstr, peeraddrstr,
                         c->line->dest_ctx.address_protocol == kSapTcp ? "Tcp" : "Udp");
                }
            }
            cstate->state = kSUpstream;
            if (c->line->dest_ctx.address_protocol == kSapTcp)
            {
                cstate->init_sent = true;
                self->up->upStream(self->up, newInitContext(c->line));
                if (! isAlive(c->line))
                {
                    reuseContextBuffer(c);
                    destroyContext(c);
                    return;
                }
                if (bufLen(bytes) > 0)
                {
                    context_t *updata  = newContextFrom(c);
                    updata->payload    = bytes;
                    updata->first      = true;
                    cstate->first_sent = true;
                    self->up->upStream(self->up, updata);
                }
                else
                {
                    reuseContextBuffer(c);
                }
            }
            else
            {

                if (bufLen(bytes) > 0)
                {
                    bufferStreamPush(cstate->udp_buf, bytes);
                    c->payload = NULL;

                    if (! processUdp(self, cstate, c->line, c->src_io))
                    {
                        LOGE("Socks5Server: udp packet could not be parsed");
                        if (cstate->init_sent)
                        {
                            self->up->upStream(self->up, newFinContext(c->line));
                        }
                        goto disconnect;
                    }
                    else
                    {
                        destroyContext(c);
                    }
                }
                else
                {
                    reuseContextBuffer(c);
                }
                // socks5 outbound connected
                socks5_server_con_state_t *cstate  = CSTATE(c);
                shift_buffer_t *           respbuf = popBuffer(getContextBufferPool(c));
                setLen(respbuf, 32);
                uint8_t *resp = rawBufMut(respbuf);
                memset(resp, 0, 32);
                resp[0]               = SOCKS5_VERSION;
                resp[1]               = kSuccessReply;
                unsigned int resp_len = 3;

                switch (c->line->dest_ctx.address.sa.sa_family)
                {
                case AF_INET:
                    resp[resp_len++] = kIPv4Addr;
                    memcpy(resp + resp_len, &c->line->dest_ctx.address.sin.sin_addr, 4);
                    resp_len += 4;
                    memcpy(resp + resp_len, &c->line->dest_ctx.address.sin.sin_port, 2);
                    resp_len += 2;

                    break;

                case AF_INET6:
                    resp[resp_len++] = kIPv6Addr;
                    memcpy(resp + resp_len, &c->line->dest_ctx.address.sin6.sin6_addr, 16);
                    resp_len += 16;
                    memcpy(resp + resp_len, &c->line->dest_ctx.address.sin6.sin6_port, 2);
                    resp_len += 2;
                    break;

                default:
                    // connects to a ip4 or 6 right? anyways close if thats not the case
                    reuseBuffer(getContextBufferPool(c), respbuf);
                    goto disconnect;
                    break;
                }
                setLen(respbuf, resp_len);
                context_t *success_reply = newContextFrom(c);
                success_reply->payload   = respbuf;
                self->dw->downStream(self->dw, success_reply);
                if (! isAlive(c->line))
                {
                    destroyContext(c);
                    return;
                }
            }

            destroyContext(c);
            return;
        }
        break;

        default:
            reuseContextBuffer(c);
            goto disconnect;
            break;
        }
    }
    else
    {
        if (c->init)
        {
            cstate = malloc(sizeof(socks5_server_con_state_t));
            memset(cstate, 0, sizeof(socks5_server_con_state_t));
            cstate->need  = 2;
            CSTATE_MUT(c) = cstate;
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = cstate->init_sent;
            cleanup(cstate, getContextBufferPool(c));
            free(cstate);
            CSTATE_MUT(c) = NULL;
            if (init_sent)
            {
                self->up->upStream(self->up, c);
            }
            else
            {
                destroyContext(c);
            }
        }
    }
    return;
disconnect:;
    cleanup(cstate, getContextBufferPool(c));
    free(cstate);
    CSTATE_MUT(c) = NULL;
    context_t *fc = newFinContextFrom(c);
    destroyContext(c);
    self->dw->downStream(self->dw, fc);
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        socks5_server_con_state_t *cstate = CSTATE(c);
        cleanup(cstate, getContextBufferPool(c));
        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
    if (c->line->dest_ctx.address_protocol == kSapTcp && c->est)
    {
        // socks5 outbound connected
        socks5_server_con_state_t *cstate  = CSTATE(c);
        shift_buffer_t *           respbuf = popBuffer(getContextBufferPool(c));
        setLen(respbuf, 32);
        uint8_t *resp = rawBufMut(respbuf);
        memset(resp, 0, 32);
        resp[0]               = SOCKS5_VERSION;
        resp[1]               = kSuccessReply;
        unsigned int resp_len = 3;

        switch (c->line->dest_ctx.address.sa.sa_family)
        {
        case AF_INET:
            resp[resp_len++] = kIPv4Addr;
            memcpy(resp + resp_len, &c->line->dest_ctx.address.sin.sin_addr, 4);
            resp_len += 4;
            memcpy(resp + resp_len, &c->line->dest_ctx.address.sin.sin_port, 2);
            resp_len += 2;

            break;

        case AF_INET6:
            resp[resp_len++] = kIPv6Addr;
            memcpy(resp + resp_len, &c->line->dest_ctx.address.sin6.sin6_addr, 16);
            resp_len += 16;
            memcpy(resp + resp_len, &c->line->dest_ctx.address.sin6.sin6_port, 2);
            resp_len += 2;
            break;

        default:
            // connects to a ip4 or 6 right? anyways close if thats not the case
            cleanup(cstate, getContextBufferPool(c));
            free(cstate);
            CSTATE_MUT(c) = NULL;
            reuseBuffer(getContextBufferPool(c), respbuf);
            self->up->upStream(self->dw, newFinContext(c->line));
            context_t *fc = newFinContextFrom(c);
            destroyContext(c);
            self->dw->downStream(self->dw, fc);
            return;
            break;
        }
        setLen(respbuf, resp_len);
        context_t *success_reply = newContextFrom(c);
        success_reply->payload   = respbuf;
        self->dw->downStream(self->dw, success_reply);
        if (! isAlive(c->line))
        {
            destroyContext(c);
            return;
        }
    }
    if (c->line->dest_ctx.address_protocol == kSapUdp && c->payload != NULL)
    {
        encapsultaeUdpPacket(c);
    }
    self->dw->downStream(self->dw, c);
}

tunnel_t *newSocks5Server(node_instance_context_t *instance_info)
{
    (void) instance_info;
    socks5_server_state_t *state = malloc(sizeof(socks5_server_state_t));
    memset(state, 0, sizeof(socks5_server_state_t));

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);
    return t;
}
api_result_t apiSocks5Server(tunnel_t *self, const char *msg)
{
    (void) self;
    (void) msg;
    return (api_result_t){0};
}

tunnel_t *destroySocks5Server(tunnel_t *self)
{
    (void) self;
    return NULL;
}

tunnel_metadata_t getMetadataSocks5Server()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
