#include "trojan_socks_server.h"
#include "loggers/network_logger.h"
#include "utils/userutils.h"
#include "utils/stringutils.h"
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

} trojan_socks_server_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{
    if (c->payload != NULL)
    {

        if (c->first)
        {

            enum trojan_cmd cmd = (unsigned char)rawBuf(c->payload)[0];
            enum trojan_atyp atyp = (unsigned char)rawBuf(c->payload)[1];
            shiftr(c->payload, 2);

            socket_context_t *dest = &(c->line->dest_ctx);
            dest->acmd = (enum socket_address_cmd)(cmd);
            dest->atype = (enum socket_address_type)(atyp);

            switch (cmd)
            {
            case TROJANCMD_CONNECT:
                dest->protocol = IPPROTO_TCP;
                switch (atyp)
                {
                case TROJANATYP_IPV4:
                    if (bufLen(c->payload) < 4)
                    {
                        DISCARD_CONTEXT(c);
                        goto failed;
                    }
                    dest->addr.sa.sa_family = AF_INET;
                    memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 4);

                    shiftr(c->payload, 4);

                    LOGD("TrojanSocksServer: connect ipv4");

                    break;
                case TROJANATYP_DOMAINNAME:
                    // TODO this should be done in router node or am i wrong?
                    if (bufLen(c->payload) < 1)
                    {
                        DISCARD_CONTEXT(c);
                        goto failed;
                    }
                    size_t addr_len = (unsigned char)(rawBuf(c->payload)[0]);
                    shiftr(c->payload, 1);
                    if (bufLen(c->payload) < addr_len)
                    {
                        DISCARD_CONTEXT(c);
                        goto failed;
                    }

                    LOGD("TrojanSocksServer: wants domain %.*s", addr_len, rawBuf(c->payload));
                    char domain[260];
                    memcpy(domain, rawBuf(c->payload), addr_len);
                    domain[addr_len] = 0;

                    struct timeval tv1, tv2;
                    gettimeofday(&tv1, NULL);
                    /* resolve domain */
                    {
                        if (sockaddr_set_ip(&(dest->addr), domain) != 0)
                        {
                            LOGE("TrojanSocksServer: resolve failed  %.*s", addr_len, rawBuf(c->payload));
                            DISCARD_CONTEXT(c);
                            goto failed;
                        }
                        else
                        {
                            char ip[60];
                            sockaddr_str(&(dest->addr), ip, 60);
                            LOGD("TrojanSocksServer: %.*s resolved to %.*s", addr_len, rawBuf(c->payload), strlen(ip), ip);
                        }
                    }
                    gettimeofday(&tv2, NULL);

                    double time_spent = (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +(double)(tv2.tv_sec - tv1.tv_sec);
                    LOGD("TrojanSocksServer: dns resolve took %lf sec", time_spent);

                    dest->resolved = true;
                    shiftr(c->payload, addr_len);

                    break;
                case TROJANATYP_IPV6:
                    if (bufLen(c->payload) < 16)
                    {
                        DISCARD_CONTEXT(c);
                        goto failed;
                    }
                    dest->addr.sa.sa_family = AF_INET6;
                    memcpy(&(dest->addr.sin.sin_addr), rawBuf(c->payload), 16);

                    shiftr(c->payload, 16);
                    LOGD("TrojanSocksServer: connect ipv6");

                    /* code */
                    break;

                default:
                    LOGD("TrojanSocksServer: atyp was incorrect (%02X) ", (unsigned int)(atyp));
                    DISCARD_CONTEXT(c);
                    goto failed;
                    break;
                }
                break;
            case TROJANCMD_UDP_ASSOCIATE:
                dest->protocol = IPPROTO_UDP;

                LOGE("TrojanSocksServer: UDP not yet");
                DISCARD_CONTEXT(c);
                break;

            default:
                LOGE("TrojanSocksServer: cmd was incorrect (%02X) ", (unsigned int)(cmd));
                DISCARD_CONTEXT(c);
                goto failed;
                break;
            }
            // port(2) + crlf(2)
            if (bufLen(c->payload) < 4)
            {
                DISCARD_CONTEXT(c);
                goto failed;
            }
            uint16_t port = 0;
            memcpy(&port, rawBuf(c->payload), 2);
            port = (port << 8) | (port >> 8);
            if (port == 0)
            {
                LOGE("OSEUOA");
            }
            sockaddr_set_port(&(dest->addr), port);
            shiftr(c->payload, 4);
            if (dest->addr.sin.sin_port == 0)
            {
                LOGE("OSEUOA");
            }

            context_t *up_init_ctx = newContext(c->line);
            up_init_ctx->init = true;
            up_init_ctx->src_io = c->src_io;
            self->up->upStream(self->up, up_init_ctx);
            if (!ISALIVE(c))
            {
                LOGW("TrojanSocksServer: next node instantly closed the init with fin");
                DISCARD_CONTEXT(c);
                return;
            }
            CSTATE(c)->init_sent = true;

            if (bufLen(c->payload) <= 0)
            {
                DISCARD_CONTEXT(c);
                destroyContext(c);
                return;
            }
            self->up->upStream(self->up, c);
            return;
        }
        else
        {
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
        }
        else if (c->fin)
        {
            bool init_sent = CSTATE(c)->init_sent;
            free(CSTATE(c));
            CSTATE_MUT(c) = NULL;
            if (init_sent)
            {
                self->up->upStream(self->up, c);
            }
        }
    }

    return;
failed:
    context_t *reply = newContext(c->line);
    reply->fin = true;
    destroyContext(c);
    self->dw->downStream(self->dw, reply);
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{

    self->dw->downStream(self->dw, c);

    return;
}

static void TrojanSocksServerUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void TrojanSocksServerPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void TrojanSocksServerDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void TrojanSocksServerPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newTrojanSocksServer(node_instance_context_t *instance_info)
{
    trojan_socks_server_state_t *state = malloc(sizeof(trojan_socks_server_state_t));
    memset(state, 0, sizeof(trojan_socks_server_state_t));

    tunnel_t *t = newTunnel();
    t->state = state;
    t->upStream = &TrojanSocksServerUpStream;
    t->packetUpStream = &TrojanSocksServerPacketUpStream;
    t->downStream = &TrojanSocksServerDownStream;
    t->packetDownStream = &TrojanSocksServerPacketDownStream;
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
