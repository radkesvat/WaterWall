#include "openssl_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "openssl_globals.h"
#include "utils/jsonutils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

typedef struct oss_client_state_s
{

    ssl_ctx_t *threadlocal_ssl_context;
    // settings
    char *alpn;
    char *sni;
    bool  verify;

} oss_client_state_t;

typedef struct oss_client_con_state_s
{
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    context_queue_t *queue;
    bool             handshake_completed;

} oss_client_con_state_t;

enum sslstatus
{
    kSslstatusOk,
    kSslstatusWantIo,
    kSslstatusFail
};

static enum sslstatus getSslStatus(SSL *ssl, int n)
{
    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:
        return kSslstatusOk;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return kSslstatusWantIo;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return kSslstatusFail;
    }
}

static void cleanup(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);
    SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
    contextqueueDestory(cstate->queue);
    memoryFree(cstate);
    CSTATE_DROP(c);
}

static void flushWriteQueue(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    while (lineIsAlive(c->line) && contextqueueLen(cstate->queue) > 0)
    {
        self->upStream(self, contextqueuePop(cstate->queue));
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    oss_client_state_t *state = TSTATE(self);

    if (c->payload != NULL)
    {
        oss_client_con_state_t *cstate = CSTATE(c);

        if (! cstate->handshake_completed)
        {
            contextqueuePush(cstate->queue, c);
            return;
        }

        enum sslstatus status;
        int            len = (int) sbufGetBufLength(c->payload);

        while (len > 0 && lineIsAlive(c->line))
        {
            int n  = SSL_write(cstate->ssl, sbufGetRawPtr(c->payload), len);
            status = getSslStatus(cstate->ssl, n);

            if (n > 0)
            {
                /* sbufConsume the waiting bytes that have been used by SSL */
                sbufShiftRight(c->payload, n);
                len -= n;
                /* take the output of the SSL object and queue it for socket write */
                do
                {
                    sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                    int             avail = (int) sbufGetRightCapacity(buf);
                    n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), avail);
                    if (n > 0)
                    {
                        sbufSetLength(buf, n);
                        context_t *send_context = contextCreateFrom(c);
                        send_context->payload   = buf;
                        self->up->upStream(self->up, send_context);
                        if (! lineIsAlive(c->line))
                        {
                            contextReusePayload(c);
                            contextDestroy(c);
                            return;
                        }
                    }
                    else if (! BIO_should_retry(cstate->wbio))
                    {
                        // If BIO_should_retry() is false then the cause is an error condition.
                        bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                        contextReusePayload(c);
                        goto failed;
                    }
                    else
                    {
                        bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                    }
                } while (n > 0);
            }

            if (status == kSslstatusFail)
            {
                contextReusePayload(c);
                goto failed;
            }

            if (n == 0)
            {
                break;
            }
        }
        assert(sbufGetBufLength(c->payload) == 0);
        contextReusePayload(c);
        contextDestroy(c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c)                  = memoryAllocate(sizeof(oss_client_con_state_t));
            oss_client_con_state_t *cstate = CSTATE(c);
            memorySet(cstate, 0, sizeof(oss_client_con_state_t));
            cstate->rbio  = BIO_new(BIO_s_mem());
            cstate->wbio  = BIO_new(BIO_s_mem());
            cstate->ssl   = SSL_new(state->threadlocal_ssl_context[c->line->tid]);
            cstate->queue = contextqueueCreate();
            SSL_set_connect_state(cstate->ssl); /* sets ssl to work in client mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            SSL_set_tlsext_host_name(cstate->ssl, state->sni);
            context_t *client_hello_ctx = contextCreateFrom(c);
            self->up->upStream(self->up, c);
            if (! lineIsAlive(client_hello_ctx->line))
            {
                contextDestroy(client_hello_ctx);
                return;
            }

            // printSSLState(cstate->ssl);
            int n = SSL_connect(cstate->ssl);
            // printSSLState(cstate->ssl);
            enum sslstatus status = getSslStatus(cstate->ssl, n);
            /* Did SSL request to write bytes? */
            if (status == kSslstatusWantIo)
            {
                sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(client_hello_ctx));
                int             avail = (int) sbufGetRightCapacity(buf);
                n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), avail);
                if (n > 0)
                {
                    sbufSetLength(buf, n);
                    client_hello_ctx->payload = buf;
                    self->up->upStream(self->up, client_hello_ctx);
                }
                else if (! BIO_should_retry(cstate->rbio))
                {
                    // If BIO_should_retry() is false then the cause is an error condition.
                    bufferpoolResuesBuffer(contextGetBufferPool(client_hello_ctx), buf);
                    goto failed;
                }
                else
                {
                    bufferpoolResuesBuffer(contextGetBufferPool(client_hello_ctx), buf);
                }
            }
            if (status == kSslstatusFail)
            {
                goto failed;
            }
        }
        else if (c->fin)
        {

            cleanup(self, c);
            self->up->upStream(self->up, c);
        }
    }

    return;

failed:
    self->up->upStream(self->up, contextCreateFinFrom(c));

    context_t *fail_context = contextCreateFinFrom(c);
    cleanup(self, c);
    contextDestroy(c);
    self->dw->downStream(self->dw, fail_context);
}

static void downStream(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        int            n;
        enum sslstatus status;

        int len = (int) sbufGetBufLength(c->payload);

        while (len > 0 && lineIsAlive(c->line))
        {
            n = BIO_write(cstate->rbio, sbufGetRawPtr(c->payload), len);

            if (n <= 0)
            {
                /* if BIO write fails, assume unrecoverable */
                contextReusePayload(c);
                goto failed;
            }
            sbufShiftRight(c->payload, n);
            len -= n;

            if (! cstate->handshake_completed)
            {
                // printSSLState(cstate->ssl);
                n = SSL_connect(cstate->ssl);
                // printSSLState(cstate->ssl);
                status = getSslStatus(cstate->ssl, n);

                /* Did SSL request to write bytes? */
                if (status == kSslstatusWantIo)
                {
                    do
                    {
                        sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                        int             avail = (int) sbufGetRightCapacity(buf);
                        n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), avail);

                        if (n > 0)
                        {
                            sbufSetLength(buf, n);
                            context_t *req_cont = contextCreateFrom(c);
                            req_cont->payload   = buf;
                            self->up->upStream(self->up, req_cont);
                            if (! lineIsAlive(c->line))
                            {
                                contextReusePayload(c);
                                contextDestroy(c);
                                return;
                            }
                        }
                        else if (! BIO_should_retry(cstate->rbio))
                        {
                            // If BIO_should_retry() is false then the cause is an error condition.
                            contextReusePayload(c);
                            bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                            goto failed;
                        }
                        else
                        {
                            bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                        }
                    } while (n > 0);
                }
                if (status == kSslstatusFail)
                {
                    SSL_get_verify_result(cstate->ssl);
                    printSSLError();
                    contextReusePayload(c);
                    goto failed;
                }

                /* Did SSL request to write bytes? */
                sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                int             avail = (int) sbufGetRightCapacity(buf);
                n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), avail);
                if (n > 0)
                {
                    sbufSetLength(buf, n);
                    context_t *data_ctx = contextCreate(c->line);
                    data_ctx->payload   = buf;
                    self->up->upStream(self->up, data_ctx);
                    if (! lineIsAlive(c->line))
                    {
                        contextReusePayload(c);
                        contextDestroy(c);
                        return;
                    }
                }
                else
                {
                    bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                }

                if (! cstate->handshake_completed && SSL_is_init_finished(cstate->ssl))
                {
                    LOGD("OpensslClient: Tls handshake complete");
                    cstate->handshake_completed = true;
                    flushWriteQueue(self, c);

                    context_t *dw_est_ctx = contextCreateFrom(c);
                    dw_est_ctx->est       = true;
                    self->dw->downStream(self->dw, dw_est_ctx);

                    // queue is flushed and we are done
                    // contextReusePayload(c);
                    // contextDestroy(c);
                    // return;
                }

                contextReusePayload(c);
                contextDestroy(c);
                return;
            }

            /* The encrypted data is now in the input bio so now we can perform actual
             * read of unencrypted data. */

            do
            {
                sbuf_t *buf = bufferpoolGetLargeBuffer(contextGetBufferPool(c));

                sbufSetLength(buf, 0);
                int avail = (int) sbufGetRightCapacity(buf);
                n         = SSL_read(cstate->ssl, sbufGetMutablePtr(buf), avail);

                if (n > 0)
                {
                    sbufSetLength(buf, n);
                    context_t *data_ctx = contextCreateFrom(c);
                    data_ctx->payload   = buf;
                    self->dw->downStream(self->dw, data_ctx);
                    if (! lineIsAlive(c->line))
                    {
                        contextReusePayload(c);
                        contextDestroy(c);
                        return;
                    }
                }
                else
                {
                    bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                }

            } while (n > 0);

            status = getSslStatus(cstate->ssl, n);

            if (status == kSslstatusFail)
            {
                contextReusePayload(c);
                goto failed;
            }
        }
        // done with socket data
        contextReusePayload(c);
        contextDestroy(c);
    }
    else
    {
        if (c->fin)
        {
            cleanup(self, c);
            self->dw->downStream(self->dw, c);
        }
        else
        {
            contextDestroy(c);
        }
    }

    return;

failed: {
    context_t *fail_context_up = contextCreateFinFrom(c);
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = contextCreateFinFrom(c);
    cleanup(self, c);
    contextDestroy(c);
    self->dw->downStream(self->dw, fail_context);
}
}

tunnel_t *newOpenSSLClient(node_instance_context_t *instance_info)
{
    oss_client_state_t *state = memoryAllocate(sizeof(oss_client_state_t));
    memorySet(state, 0, sizeof(oss_client_state_t));

    state->threadlocal_ssl_context = memoryAllocate(sizeof(ssl_ctx_t) * getWorkersCount());

    ssl_ctx_opt_t *ssl_param = memoryAllocate(sizeof(ssl_ctx_opt_t));
    memorySet(ssl_param, 0, sizeof(ssl_ctx_opt_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: OpenSSLClient->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->sni), settings, "sni"))
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty or invalid");
        return NULL;
    }
    if (strlen(state->sni) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty");
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&(state->verify), settings, "verify", true);

    getStringFromJsonObjectOrDefault(&(state->alpn), settings, "alpn", "http/1.1");

    ssl_param->verify_peer = state->verify ? 1 : 0;
    ssl_param->endpoint    = kSslClient;

    size_t alpn_len = strlen(state->alpn);

    struct
    {
        uint8_t len;
        char    alpn_data[];
    } *ossl_alpn = memoryAllocate(1 + alpn_len);

    ossl_alpn->len = alpn_len;
    memoryCopy(&(ossl_alpn->alpn_data[0]), state->alpn, alpn_len);

    for (unsigned int i = 0; i < getWorkersCount(); i++)
    {
        state->threadlocal_ssl_context[i] = sslCtxNew(ssl_param);

        if (state->threadlocal_ssl_context[i] == NULL)
        {
            LOGF("RealityClient: Could not create ssl context");
            return NULL;
        }

        SSL_CTX_set_alpn_protos(state->threadlocal_ssl_context[i], (const unsigned char *) ossl_alpn, 1 + alpn_len);
    }

    memoryFree(ssl_param);
    memoryFree(ossl_alpn);

    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiOpenSSLClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyOpenSSLClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataOpenSSLClient(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
