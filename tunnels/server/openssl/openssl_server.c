#include "openssl_server.h"
#include "buffer_pool.h"
#include "managers/socket_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include <time.h>
#include <string.h>

#define STATE(x) ((oss_server_state_t *)((x)->state))
#define CSTATE(x) ((oss_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]

typedef struct oss_server_state_s
{

    hssl_ctx_t ssl_context;
    // settings

    char *address;
    int multiport_backend;
    uint16_t port_min;
    uint16_t port_max;
    char **white_list_raddr;
    char **black_list_raddr;
    bool fast_open;

} oss_server_state_t;

typedef struct oss_server_con_state_s
{

    hssl_t ssl_context;

} oss_server_con_state_t;

static inline void upStream(tunnel_t *self, context_t *c)
{

    if (c->payload != NULL)
    {
        self->up->upStream(self->up, redir_context);
    }
    else
    {
        if (c->fin)
        {
            CSTATE_MUT(c) = malloc(sizeof(oss_server_state_t));
            memset(CSTATE(c), 0, sizeof(oss_server_state_t));
            
            if (connio->ssl == NULL)
            {
                // io->ssl_ctx > g_ssl_ctx > hssl_ctx_new
                hssl_ctx_t ssl_ctx = NULL;
                if (io->ssl_ctx)
                {
                    ssl_ctx = io->ssl_ctx;
                }
                else if (g_ssl_ctx)
                {
                    ssl_ctx = g_ssl_ctx;
                }
                else
                {
                    io->ssl_ctx = ssl_ctx = hssl_ctx_new(NULL);
                    io->alloced_ssl_ctx = 1;
                }
                if (ssl_ctx == NULL)
                {
                    io->error = ERR_NEW_SSL_CTX;
                    goto accept_error;
                }
                hssl_t ssl = hssl_new(ssl_ctx, connfd);
                if (ssl == NULL)
                {
                    io->error = ERR_NEW_SSL;
                    goto accept_error;
                }
                connio->ssl = ssl;
            }
        }
        else if (c->first)
        {
        }
    }
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    tcp_listener_con_state_t *cstate = CSTATE(c);
    if (c->payload != NULL)
    {
        self->dw->downStream(self->dw, ctx);
    }
    else
    {
        if (c->est)
        {
        }
        else if (c->fin)
        {
        }
    }
}

static bool check_libhv()
{
    if (!HV_WITH_SSL())
    {
        LOGF("OpenSSL-Server: libhv compiled without ssl backend");
        return false;
    }
    if (strcmp(hssl_backend(), "openssl") != 0)
    {
        LOGF("OpenSSL-Server: wrong ssl backend in libhv, expecetd: %s but found %s", "openssl", hssl_backend());
        return false;
    }
    return true;
}

tunnel_t *newOpenSSLServer(node_instance_context_t *instance_info)
{
    if (!check_libhv())
    {
        return NULL;
    }

    oss_server_state_t *state = malloc(sizeof(oss_server_state_t));
    memset(state, 0, sizeof(oss_server_state_t));

    hssl_ctx_opt_t ssl_param;
    memset(&ssl_param, 0, sizeof(ssl_param));
    ssl_param.crt_file = "cert/server.crt";
    ssl_param.key_file = "cert/server.key";
    ssl_param.endpoint = HSSL_SERVER;
    state->ssl_context = hssl_ctx_new(opt);
}

void apiOpenSSLServer(tunnel_t *self, char *msg)
{
}

tunnel_t *destroyOpenSSLServer(tunnel_t *self)
{
    return nullptr;
}
