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

    ssl_ctx_t ssl_context;
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
    if (cstate != NULL)
    {
        SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
        destroyContextQueue(cstate->queue);

        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
}

static void flushWriteQueue(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    while (contextQueueLen(cstate->queue) > 0)
    {
        self->upStream(self, contextQueuePop(cstate->queue));

        if (! isAlive(c->line))
        {
            return;
        }
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    oss_client_state_t *state = STATE(self);

    if (c->payload != NULL)
    {
        oss_client_con_state_t *cstate = CSTATE(c);

        if (! cstate->handshake_completed)
        {
            contextQueuePush(cstate->queue, c);
            return;
        }

        enum sslstatus status;
        int            len = (int) bufLen(c->payload);

        while (len > 0)
        {
            int n  = SSL_write(cstate->ssl, rawBuf(c->payload), len);
            status = getSslStatus(cstate->ssl, n);

            if (n > 0)
            {
                /* consume the waiting bytes that have been used by SSL */
                shiftr(c->payload, n);
                len -= n;
                /* take the output of the SSL object and queue it for socket write */
                do
                {
                    shift_buffer_t *buf   = popBuffer(getContextBufferPool(c));
                    int             avail = (int) rCap(buf);
                    n                     = BIO_read(cstate->wbio, rawBufMut(buf), avail);
                    if (n > 0)
                    {
                        setLen(buf, n);
                        context_t *send_context = newContextFrom(c);
                        send_context->payload   = buf;
                        self->up->upStream(self->up, send_context);
                        if (! isAlive(c->line))
                        {
                            reuseContextBuffer(c);
                            destroyContext(c);
                            return;
                        }
                    }
                    else if (! BIO_should_retry(cstate->wbio))
                    {
                        // If BIO_should_retry() is false then the cause is an error condition.
                        reuseBuffer(getContextBufferPool(c), buf);
                        reuseContextBuffer(c);
                        goto failed;
                    }
                    else
                    {
                        reuseBuffer(getContextBufferPool(c), buf);
                    }
                } while (n > 0);
            }

            if (status == kSslstatusFail)
            {
                reuseContextBuffer(c);
                goto failed;
            }

            if (n == 0)
            {
                break;
            }
        }
        assert(bufLen(c->payload) == 0);
        reuseContextBuffer(c);
        destroyContext(c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(oss_client_con_state_t));
            memset(CSTATE(c), 0, sizeof(oss_client_con_state_t));
            oss_client_con_state_t *cstate = CSTATE(c);
            cstate->rbio                   = BIO_new(BIO_s_mem());
            cstate->wbio                   = BIO_new(BIO_s_mem());
            cstate->ssl                    = SSL_new(state->ssl_context);
            cstate->queue                  = newContextQueue(getContextBufferPool(c));
            SSL_set_connect_state(cstate->ssl); /* sets ssl to work in client mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            SSL_set_tlsext_host_name(cstate->ssl, state->sni);
            context_t *client_hello_ctx = newContextFrom(c);
            self->up->upStream(self->up, c);
            if (! isAlive(client_hello_ctx->line))
            {
                destroyContext(client_hello_ctx);
                return;
            }

            // printSSLState(cstate->ssl);
            int n = SSL_connect(cstate->ssl);
            // printSSLState(cstate->ssl);
            enum sslstatus status = getSslStatus(cstate->ssl, n);
            /* Did SSL request to write bytes? */
            if (status == kSslstatusWantIo)
            {
                shift_buffer_t *buf   = popBuffer(getContextBufferPool(client_hello_ctx));
                int             avail = (int) rCap(buf);
                n                     = BIO_read(cstate->wbio, rawBufMut(buf), avail);
                if (n > 0)
                {
                    setLen(buf, n);
                    client_hello_ctx->payload = buf;
                    client_hello_ctx->first   = true;
                    self->up->upStream(self->up, client_hello_ctx);
                }
                else if (! BIO_should_retry(cstate->rbio))
                {
                    // If BIO_should_retry() is false then the cause is an error condition.
                    reuseBuffer(getContextBufferPool(client_hello_ctx), buf);
                    goto failed;
                }
                else
                {
                    reuseBuffer(getContextBufferPool(client_hello_ctx), buf);
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

failed:;
    self->up->upStream(self->up, newFinContextFrom(c));

    context_t *fail_context = newFinContextFrom(c);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
}

static void downStream(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        int            n;
        enum sslstatus status;

        int len = (int) bufLen(c->payload);

        while (len > 0)
        {
            n = BIO_write(cstate->rbio, rawBuf(c->payload), len);

            if (n <= 0)
            {
                /* if BIO write fails, assume unrecoverable */
                reuseContextBuffer(c);
                goto failed;
            }
            shiftr(c->payload, n);
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
                        shift_buffer_t *buf   = popBuffer(getContextBufferPool(c));
                        int             avail = (int) rCap(buf);
                        n                     = BIO_read(cstate->wbio, rawBufMut(buf), avail);

                        if (n > 0)
                        {
                            setLen(buf, n);
                            context_t *req_cont = newContextFrom(c);
                            req_cont->payload   = buf;
                            self->up->upStream(self->up, req_cont);
                            if (! isAlive(c->line))
                            {
                                reuseContextBuffer(c);
                                destroyContext(c);
                                return;
                            }
                        }
                        else if (! BIO_should_retry(cstate->rbio))
                        {
                            // If BIO_should_retry() is false then the cause is an error condition.
                            reuseContextBuffer(c);
                            reuseBuffer(getContextBufferPool(c), buf);
                            goto failed;
                        }
                        else
                        {
                            reuseBuffer(getContextBufferPool(c), buf);
                        }
                    } while (n > 0);
                }
                if (status == kSslstatusFail)
                {
                    SSL_get_verify_result(cstate->ssl);
                    printSSLError();
                    reuseContextBuffer(c);
                    goto failed;
                }

                /* Did SSL request to write bytes? */
                shift_buffer_t *buf   = popBuffer(getContextBufferPool(c));
                int             avail = (int) rCap(buf);
                n                     = BIO_read(cstate->wbio, rawBufMut(buf), avail);
                if (n > 0)
                {
                    setLen(buf, n);
                    context_t *data_ctx = newContext(c->line);
                    data_ctx->payload   = buf;
                    self->up->upStream(self->up, data_ctx);
                }
                else
                {
                    reuseBuffer(getContextBufferPool(c), buf);
                }

                if (!cstate->handshake_completed && SSL_is_init_finished(cstate->ssl) )
                {
                    LOGD("OpensslClient: Tls handshake complete");
                    cstate->handshake_completed = true;
                    flushWriteQueue(self, c);

                    if (! isAlive(c->line))
                    {
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }

                    context_t *dw_est_ctx = newContextFrom(c);
                    dw_est_ctx->est       = true;
                    self->dw->downStream(self->dw, dw_est_ctx);

                    // queue is flushed and we are done
                    // reuseContextBuffer(c);
                    // destroyContext(c);
                    // return;
                }

                reuseContextBuffer(c);
                destroyContext(c);
                return;
            }

            /* The encrypted data is now in the input bio so now we can perform actual
             * read of unencrypted data. */

            do
            {
                shift_buffer_t *buf = popBuffer(getContextBufferPool(c));
                shiftl(buf, 8192 / 2);
                setLen(buf, 0);
                int avail = (int) rCap(buf);
                n         = SSL_read(cstate->ssl, rawBufMut(buf), avail);

                if (n > 0)
                {
                    setLen(buf, n);
                    context_t *data_ctx = newContextFrom(c);
                    data_ctx->payload   = buf;
                    self->dw->downStream(self->dw, data_ctx);
                    if (! isAlive(c->line))
                    {
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                }
                else
                {
                    reuseBuffer(getContextBufferPool(c), buf);
                }

            } while (n > 0);

            status = getSslStatus(cstate->ssl, n);

            if (status == kSslstatusFail)
            {
                reuseContextBuffer(c);
                goto failed;
            }
        }
        // done with socket data
        reuseContextBuffer(c);
        destroyContext(c);
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
            destroyContext(c);
        }
    }

    return;

failed:;
    context_t *fail_context_up = newFinContextFrom(c);
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newFinContextFrom(c);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
}

tunnel_t *newOpenSSLClient(node_instance_context_t *instance_info)
{
    oss_client_state_t *state = malloc(sizeof(oss_client_state_t));
    memset(state, 0, sizeof(oss_client_state_t));

    ssl_ctx_opt_t *ssl_param = malloc(sizeof(ssl_ctx_opt_t));
    memset(ssl_param, 0, sizeof(ssl_ctx_opt_t));
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
    // ssl_param->ca_path = "cacert.pem";
    state->ssl_context = sslCtxNew(ssl_param);
    free(ssl_param);
    // SSL_CTX_load_verify_store(state->ssl_context,cacert_bytes);

    if (state->ssl_context == NULL)
    {
        LOGF("OpenSSLClient: Could not create ssl context");
        return NULL;
    }

    size_t alpn_len = strlen(state->alpn);
    struct
    {
        uint8_t len;
        char    alpn_data[];
    } *ossl_alpn   = malloc(1 + alpn_len);
    ossl_alpn->len = alpn_len;
    memcpy(&(ossl_alpn->alpn_data[0]), state->alpn, alpn_len);
    SSL_CTX_set_alpn_protos(state->ssl_context, (const unsigned char *) ossl_alpn, 1 + alpn_len);
    free(ossl_alpn);

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiOpenSSLClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyOpenSSLClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataOpenSSLClient(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
