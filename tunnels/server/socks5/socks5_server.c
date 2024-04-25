#include "socks5_server.h"

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

typedef struct
{
    hio_t *          io;
    socks5_state_e   state;
    socks5_addr_type addr_type;
    sockaddr_u       addr;
} socks5_conn_t;

typedef struct socks5_server_state_s
{

} socks5_server_state_t;

typedef struct socks5_server_con_state_s
{
    bool            authenticated;
    bool            init_sent;
    bool            first_sent;
    socks5_state_e  state;
    shift_buffer_t *waitbuf;
    unsigned int    need;
} socks5_server_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{
    socks5_server_state_t *    state  = STATE(self);
    socks5_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (cstate->init_sent)
        {
            self->up->upStream(self->up, c);
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
        if (bufLen(c->payload) > cstate->need)
        {
            reuseContextBuffer(c);
            goto disconnect;
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
            context_t *reply = newContextFrom(c);
            self->dw->downStream(self->dw, reply);
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

            if (version != SOCKS5_VERSION || cmd != kConnectCommand || cmd != kAssociateCommand)
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
                break;
            default:
                reuseContextBuffer(c);
                goto disconnect;
            }
            shiftr(bytes, 1);
            cstate->state = kSDstAddrType;
            cstate->need  = 1;
            goto parsebegin;
        }
        break;
        case kSDstAddrType:
            // printf("kSdst_addr_type\n");
            {
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
                memcpy(&c->line->dest_ctx.address.sin.sin_addr, bytes, 4);
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
                memcpy(&c->line->dest_ctx.address.sin6.sin6_addr, bytes, 16);
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

            cstate->init_sent = true;
            self->up->upStream(self->up, newInitContext(c->line));
            if (! isAlive(c->line))
            {
                reuseContextBuffer(c);
                goto disconnect;
            }
            if (bufLen(bytes) > 0)
            {
                context_t *updata  = newContextFrom(c);
                updata->first      = true;
                cstate->first_sent = true;
                self->up->upStream(self->up, updata);
            }
            else
            {
                reuseContextBuffer(c);
            }
            destroyContext(c);
            return;
            // uint16_t port = ((uint16_t) bytes[0]) << 8 | bytes[1];
            // // printf("port=%d\n", port);
            // sockaddr_set_port(&cstate->addr, port);
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
            cstate->need = 2;
            CSTATE_MUT(c) = cstate;
            destroyContext(c);
        }
        else if (c->fin)
        {
            bool init_sent = cstate->init_sent;
            free(CSTATE(c));
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
    free(cstate);
    CSTATE_MUT(c) = NULL;
    context_t* fc = newFinContext(c->line);
    destroyContext(c);
    self->dw->downStream(self->dw,fc);
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    if (c->fin)
    {
        free(CSTATE(c));
        CSTATE_MUT(c) = NULL;
    }
    self->dw->downStream(self->dw, c);
}

tunnel_t *newSocks5ServerServer(node_instance_context_t *instance_info)
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
api_result_t apiSocks5ServerServer(tunnel_t *self, const char *msg)
{
    (void) self;
    (void) msg;
    return (api_result_t){0};
}

tunnel_t *destroySocks5ServerServer(tunnel_t *self)
{
    (void) self;
    return NULL;
}

tunnel_metadata_t getMetadataSocks5ServerServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
