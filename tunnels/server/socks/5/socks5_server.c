#include "socks5_server.h"
#include "basic_types.h"
#include "buffer_stream.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/sockutils.h"

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
    void *_;
} socks5_server_state_t;

typedef struct socks5_server_con_state_s
{
    bool            authenticated;
    bool            established;
    bool            init_sent;
    socks5_state_e  state;
    shift_buffer_t *waitbuf;
    unsigned int    udp_data_offset;

    unsigned int need;

} socks5_server_con_state_t;

static void cleanup(socks5_server_con_state_t *cstate, buffer_pool_t *reusepool)
{
    if (cstate->waitbuf)
    {
        reuseBuffer(reusepool, cstate->waitbuf);
    }
}
static void encapsulateUdpPacket(context_t *c)
{
    shift_buffer_t *packet = c->payload;

    uint16_t port = sockaddr_port(&(c->line->dest_ctx.address));
    port          = (port << 8) | (port >> 8);
    shiftl(packet, 2); // port
    writeUnAlignedUI16(packet, port);

    switch (c->line->dest_ctx.address_type)
    {
    case kSatIPV6:
        shiftl(packet, 16);
        writeRaw(packet, &(c->line->dest_ctx.address.sin6.sin6_addr), 16);
        shiftl(packet, 1);
        writeUnAlignedUI8(packet, kIPv6Addr);
        break;

    case kSatIPV4:
    default:
        shiftl(packet, 4);
        writeRaw(packet, &(c->line->dest_ctx.address.sin.sin_addr), 4);
        shiftl(packet, 1);
        writeUnAlignedUI8(packet, kIPv4Addr);
        break;
    }
    shiftl(packet, 1);
    writeUnAlignedUI8(packet, 0x0);
    shiftl(packet, 2);
    writeUnAlignedUI16(packet, 0x0);
}

#define ATLEAST(x)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((int) bufLen(c->payload) < (x))                                                                            \
        {                                                                                                              \
            reuseContextPayload(c);                                                                                    \
            goto disconnect;                                                                                           \
        }                                                                                                              \
    } while (0);

static void udpUpStream(tunnel_t *self, context_t *c)
{
    socks5_server_con_state_t *cstate       = CSTATE(c);
    shift_buffer_t            *bytes        = c->payload;
    socket_context_t          *dest_context = &(c->line->dest_ctx);

    // minimum 10 is important
    if (bufLen(c->payload) > 8192 || bufLen(c->payload) < 10)
    {
        reuseContextPayload(c);
        goto disconnect;
    }

    if (cstate->init_sent)
    {
        // drop fargmented pcakets
        if (((uint8_t *) rawBuf(bytes))[2] != 0)
        {
            reuseContextPayload(c);
            return;
        }
        const uint8_t satyp = ((uint8_t *) rawBuf(bytes))[3];
        shiftr(bytes, 4);
        int atleast = 0;
        switch ((socks5_addr_type) satyp)
        {
        case kIPv4Addr:
            atleast = 4;
            break;
        case kFqdnAddr:
            dest_context->address_type = kSatDomainName;
            // already checked for at least 10 length
            const uint8_t domain_len = ((uint8_t *) rawBuf(bytes))[0];
            atleast                  = 1 + domain_len;
            break;
        case kIPv6Addr:
            atleast = 16;
            break;
        default:
            reuseContextPayload(c);
            goto disconnect;
        }
        ATLEAST(atleast);
        shiftr(bytes, atleast);
        self->up->upStream(self->up, c);
    }
    else
    {
        if (((uint8_t *) rawBuf(bytes))[0] != 0 || ((uint8_t *) rawBuf(bytes))[1] != 0 ||
            ((uint8_t *) rawBuf(bytes))[2] != 0)
        {
            reuseContextPayload(c);
            goto disconnect;
        }
        const uint8_t satyp = ((uint8_t *) rawBuf(bytes))[3];
        shiftr(bytes, 4);
        dest_context->address_protocol = kSapUdp;

        switch ((socks5_addr_type) satyp)
        {
        case kIPv4Addr:
            dest_context->address_type = kSatIPV4;
            ATLEAST(4);
            memcpy(&(dest_context->address.sin.sin_addr), rawBuf(c->payload), 4);
            shiftr(c->payload, 4);
            break;
        case kFqdnAddr:
            dest_context->address_type = kSatDomainName;
            // already checked for at least 10 length
            const uint8_t domain_len = ((uint8_t *) rawBuf(bytes))[0];
            ATLEAST(1 + domain_len);
            LOGD("Socks5Server: udp domain %.*s", domain_len, rawBuf(c->payload));
            socketContextDomainSet(dest_context, rawBuf(c->payload), domain_len);
            shiftr(c->payload, domain_len);

            break;
        case kIPv6Addr:
            dest_context->address_type = kSatIPV6;
            ATLEAST(16);
            memcpy(&(dest_context->address.sin.sin_addr), rawBuf(c->payload), 16);
            shiftr(c->payload, 16);
            break;
        default:
            reuseContextPayload(c);
            goto disconnect;
        }
        ATLEAST(2); // port
        memcpy(&(dest_context->address.sin.sin_port), rawBuf(c->payload), 2);
        shiftr(c->payload, 2);
        self->up->upStream(self->up, newInitContext(c->line));
        if (! isAlive(c->line))
        {
            LOGW("Socks5Server: udp next node instantly closed the init with fin");
            reuseContextPayload(c);
            goto disconnect;
        }
        cstate->init_sent = true;
        // send whatever left as the udp payload
        self->up->upStream(self->up, c);
    }

    return;
disconnect:
    if (cstate->init_sent)
    {
        self->up->upStream(self->up, newFinContext(c->line));
    }
    cleanup(cstate, getContextBufferPool(c));
    globalFree(cstate);
    CSTATE_DROP(c);
    context_t *fc = newFinContextFrom(c);
    destroyContext(c);
    self->dw->downStream(self->dw, fc);
}
static void upStream(tunnel_t *self, context_t *c)
{
    socks5_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (c->line->src_ctx.address_protocol == kSapUdp)
        {
            udpUpStream(self, c);
            return;
        }
        if (cstate->state == kSUpstream)
        {
            if (c->line->dest_ctx.address_protocol == kSapUdp)
            {
                reuseContextPayload(c);
                destroyContext(c);
                LOGE("Socks5Server: client is not supposed to send data anymore");
            }
            else if (c->line->dest_ctx.address_protocol == kSapTcp)
            {

                self->up->upStream(self->up, c);
            }

            return;
        }
        if (cstate->waitbuf)
        {
            c->payload      = appendBufferMerge(getContextBufferPool(c), cstate->waitbuf, c->payload);
            cstate->waitbuf = NULL;
        }
    parsebegin:

        if (bufLen(c->payload) < cstate->need)
        {
            cstate->waitbuf = c->payload;
            dropContexPayload(c);
            destroyContext(c);
            return;
        }

        shift_buffer_t *bytes = c->payload;

        switch (cstate->state)
        {
        case kSBegin:
            cstate->state = kSAuthMethodsCount;
            // fallthrough
        case kSAuthMethodsCount: {
            assert(cstate->need == 2);
            uint8_t version = 0;
            readUnAlignedUI8(bytes, &version);
            shiftr(bytes, 1);
            uint8_t methodscount = 0;
            readUnAlignedUI8(bytes, &methodscount);
            shiftr(bytes, 1);
            if (version != SOCKS5_VERSION || methodscount == 0)
            {
                LOGE("Socks5Server: Unsupprted socks version: %d", (int) version);
                reuseContextPayload(c);
                goto disconnect;
            }
            cstate->state = kSAuthMethods;
            cstate->need  = methodscount;
            goto parsebegin;
        }
        break;
        case kSAuthMethods: {
            // TODO(root): check auth methods
            // uint8_t authmethod = kNoAuth;
            // send auth mothod
            shift_buffer_t *resp = popBuffer(getContextBufferPool(c));
            shiftl(resp, 1);
            writeUnAlignedUI8(resp, kNoAuth);
            shiftl(resp, 1);
            writeUnAlignedUI8(resp, SOCKS5_VERSION);
            shiftr(bytes, cstate->need); // we've read and choosed 1 method
            context_t *reply = newContextFrom(c);
            reply->payload   = resp;
            self->dw->downStream(self->dw, reply);
            if (! isAlive(c->line))
            {
                reuseContextPayload(c);
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
            reuseContextPayload(c);
            goto disconnect;
            break;
        case kSRequest: {
            assert(cstate->need == 3);

            uint8_t version = 0;
            readUnAlignedUI8(bytes, &version);
            shiftr(bytes, 1);

            uint8_t cmd = 0;
            readUnAlignedUI8(bytes, &cmd);
            shiftr(bytes, 1);

            if (version != SOCKS5_VERSION || (cmd != kConnectCommand && cmd != kAssociateCommand))
            {
                LOGE("Socks5Server: Unsupprted command: %d", (int) cmd);
                reuseContextPayload(c);
                goto disconnect;
            }
            switch (cmd)
            {
            case kConnectCommand:
                c->line->dest_ctx.address_protocol = kSapTcp;
                break;
            case kAssociateCommand:
                c->line->dest_ctx.address_protocol = kSapUdp;
                break;
            default:
                reuseContextPayload(c);
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
            readUnAlignedUI8(bytes, &satyp);
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
                reuseContextPayload(c);
                goto disconnect;
            }
        }
        break;
        case kSDstAddrLen: {
            assert(cstate->need == 1);
            uint8_t addr_len = 0;
            readUnAlignedUI8(bytes, &addr_len);
            shiftr(bytes, 1);

            if (addr_len == 0)
            {
                LOGE("Socks5Server: incorrect domain length");
                reuseContextPayload(c);
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
                reuseContextPayload(c);
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
                    reuseContextPayload(c);
                    destroyContext(c);
                    return;
                }
                if (bufLen(bytes) > 0)
                {
                    context_t *updata = newContextFrom(c);
                    updata->payload   = bytes;
                    self->up->upStream(self->up, updata);
                }
                else
                {
                    reuseContextPayload(c);
                }
            }
            else
            {
                reuseContextPayload(c);
                // todo (ip filter) socks5 standard says this should whitelist the caller ip
                //  socks5 outbound accepted, udp relay will connect
                shift_buffer_t *respbuf = popBuffer(getContextBufferPool(c));
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
                    sockaddr_set_port(&(c->line->dest_ctx.address), sockaddr_port(&(c->line->src_ctx.address)));
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
            reuseContextPayload(c);
            goto disconnect;
            break;
        }
    }
    else
    {
        if (c->init)
        {
            cstate = globalMalloc(sizeof(socks5_server_con_state_t));
            memset(cstate, 0, sizeof(socks5_server_con_state_t));
            cstate->need  = 2;
            CSTATE_MUT(c) = cstate;
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = cstate->init_sent;
            cleanup(cstate, getContextBufferPool(c));
            globalFree(cstate);
            CSTATE_DROP(c);
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
disconnect:
    cleanup(cstate, getContextBufferPool(c));
    globalFree(cstate);
    CSTATE_DROP(c);
    context_t *fc = newFinContextFrom(c);
    destroyContext(c);
    self->dw->downStream(self->dw, fc);
}

static void downStream(tunnel_t *self, context_t *c)
{
    if (c->line->dest_ctx.address_protocol == kSapUdp && c->payload != NULL)
    {
        encapsulateUdpPacket(c);
        self->dw->downStream(self->dw, c);
        return;
    }
    if (c->fin)
    {
        socks5_server_con_state_t *cstate = CSTATE(c);

        if (! cstate->established)
        {
            cstate->init_sent = false;
            // socks5 outbound failed
            shift_buffer_t *respbuf = popBuffer(getContextBufferPool(c));
            setLen(respbuf, 32);
            uint8_t *resp = rawBufMut(respbuf);
            memset(resp, 0, 32);
            resp[0]               = SOCKS5_VERSION;
            resp[1]               = kHostUnreachable;
            unsigned int resp_len = 3;
            // [2] is reserved 0
            resp[resp_len++] = kIPv4Addr;

            setLen(respbuf, resp_len + 6); // ipv4(4) + port(2)
            context_t *fail_reply = newContextFrom(c);
            fail_reply->payload   = respbuf;
            self->dw->downStream(self->dw, fail_reply);
            if (! isAlive(c->line))
            {
                destroyContext(c);
                return;
            }
        }

        cleanup(cstate, getContextBufferPool(c));
        globalFree(cstate);
        CSTATE_DROP(c);
    }
    if (c->est)
    {
        socks5_server_con_state_t *cstate = CSTATE(c);
        cstate->established               = true;
        if (c->line->dest_ctx.address_protocol == kSapTcp)
        {
            // socks5 outbound connected
            shift_buffer_t *respbuf = popBuffer(getContextBufferPool(c));
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
                globalFree(cstate);
                CSTATE_DROP(c);
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
    }

    self->dw->downStream(self->dw, c);
}

tunnel_t *newSocks5Server(node_instance_context_t *instance_info)
{
    (void) instance_info;
    socks5_server_state_t *state = globalMalloc(sizeof(socks5_server_state_t));
    memset(state, 0, sizeof(socks5_server_state_t));

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}
api_result_t apiSocks5Server(tunnel_t *self, const char *msg)
{
    (void) self;
    (void) msg;
    return (api_result_t) {0};
}

tunnel_t *destroySocks5Server(tunnel_t *self)
{
    (void) self;
    return NULL;
}

tunnel_metadata_t getMetadataSocks5Server(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
