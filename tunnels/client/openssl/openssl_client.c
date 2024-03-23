#include "openssl_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "managers/node_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include "openssl_globals.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define STATE(x) ((oss_client_state_t *)((x)->state))
#define CSTATE(x) ((oss_client_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct oss_client_state_s
{

    ssl_ctx_t ssl_context;
    // settings
    char *alpn;
    char *sni;
    bool verify;

} oss_client_state_t;

typedef struct oss_client_con_state_s
{
    bool handshake_completed;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    context_queue_t *queue;

} oss_client_con_state_t;

enum sslstatus
{
    SSLSTATUS_OK,
    SSLSTATUS_WANT_IO,
    SSLSTATUS_FAIL
};

static enum sslstatus get_sslstatus(SSL *ssl, int n)
{
    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:
        return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return SSLSTATUS_FAIL;
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

static void flush_write_queue(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    while (contextQueueLen(cstate->queue) > 0)
    {
        self->upStream(self, contextQueuePop(cstate->queue));

        if (!ISALIVE(c))
            return;
    }
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    oss_client_state_t *state = STATE(self);

    if (c->payload != NULL)
    {
        oss_client_con_state_t *cstate = CSTATE(c);

        if (!cstate->handshake_completed)
        {
            contextQueuePush(cstate->queue, c);
            return;
        }

        enum sslstatus status;
        size_t len = bufLen(c->payload);

        while (len > 0)
        {
            int n = SSL_write(cstate->ssl, rawBuf(c->payload), len);
            status = get_sslstatus(cstate->ssl, n);

            if (n > 0)
            {
                /* consume the waiting bytes that have been used by SSL */
                shiftr(c->payload, n);
                len -= n;
                /* take the output of the SSL object and queue it for socket write */
                do
                {
                    shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                    size_t avail = rCap(buf);
                    n = BIO_read(cstate->wbio, rawBuf(buf), avail);
                    if (n > 0)
                    {
                        setLen(buf, n);
                        context_t *send_context = newContextFrom(c);
                        send_context->payload = buf;
                        self->up->upStream(self->up, send_context);
                        if (!ISALIVE(c))
                        {
                            DISCARD_CONTEXT(c);
                            destroyContext(c);
                            return;
                        }
                    }
                    else if (!BIO_should_retry(cstate->wbio))
                    {
                        // If BIO_should_retry() is false then the cause is an error condition.
                        reuseBuffer(buffer_pools[c->line->tid], buf);
                        DISCARD_CONTEXT(c);
                        goto failed;
                    }
                    else
                    {
                        reuseBuffer(buffer_pools[c->line->tid], buf);
                    }
                } while (n > 0);
            }

            if (status == SSLSTATUS_FAIL)
            {
                DISCARD_CONTEXT(c);
                goto failed;
            }

            if (n == 0)
                break;
        }
        assert(bufLen(c->payload) == 0);
        DISCARD_CONTEXT(c);
        destroyContext(c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(oss_client_con_state_t));
            memset(CSTATE(c), 0, sizeof(oss_client_con_state_t));
            oss_client_con_state_t *cstate = CSTATE(c);
            cstate->rbio = BIO_new(BIO_s_mem());
            cstate->wbio = BIO_new(BIO_s_mem());
            cstate->ssl = SSL_new(state->ssl_context);
            cstate->queue = newContextQueue(buffer_pools[c->line->tid]);
            SSL_set_connect_state(cstate->ssl); /* sets ssl to work in client mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            SSL_set_tlsext_host_name(cstate->ssl, state->sni);
            context_t *clienthello_ctx = newContextFrom(c);
            self->up->upStream(self->up, c);
            if (!ISALIVE(clienthello_ctx))
            {
                destroyContext(c);
                return;
            }

            // printSSLState(cstate->ssl);
            int n = SSL_connect(cstate->ssl);
            // printSSLState(cstate->ssl);
            enum sslstatus status = get_sslstatus(cstate->ssl, n);
            /* Did SSL request to write bytes? */
            if (status == SSLSTATUS_WANT_IO)
            {
                shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                size_t avail = rCap(buf);
                n = BIO_read(cstate->wbio, rawBuf(buf), avail);
                if (n > 0)
                {
                    setLen(buf, n);
                    clienthello_ctx->payload = buf;
                    clienthello_ctx->first = true;
                    self->up->upStream(self->up, clienthello_ctx);
                    if (!ISALIVE(c))
                    {
                        destroyContext(c);
                        return;
                    }
                }
                else if (!BIO_should_retry(cstate->rbio))
                {
                    // If BIO_should_retry() is false then the cause is an error condition.
                    reuseBuffer(buffer_pools[c->line->tid], buf);
                    goto failed;
                }
                else
                {
                    reuseBuffer(buffer_pools[c->line->tid], buf);
                }
            }
            if (status == SSLSTATUS_FAIL)
                goto failed;
        }
        else if (c->fin)
        {

            cleanup(self, c);
            self->up->upStream(self->up, c);
        }
    }

    return;

failed:
    context_t *fail_context_up = newFinContext(c->line);
    fail_context_up->src_io = c->src_io;
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newFinContext(c->line);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    oss_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        int n;
        enum sslstatus status;
        // if (!cstate->handshake_completed)

        size_t len = bufLen(c->payload);

        while (len > 0)
        {
            n = BIO_write(cstate->rbio, rawBuf(c->payload), len);

            if (n <= 0)
            {
                /* if BIO write fails, assume unrecoverable */
                DISCARD_CONTEXT(c);
                goto failed;
            }
            shiftr(c->payload, n);
            len -= n;

            if (!cstate->handshake_completed)
            {
                // printSSLState(cstate->ssl);
                n = SSL_connect(cstate->ssl);
                // printSSLState(cstate->ssl);
                status = get_sslstatus(cstate->ssl, n);

                /* Did SSL request to write bytes? */
                if (status == SSLSTATUS_WANT_IO)
                    do
                    {
                        shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                        size_t avail = rCap(buf);
                        n = BIO_read(cstate->wbio, rawBuf(buf), avail);

                        if (n > 0)
                        {
                            setLen(buf, n);
                            context_t *req_cont = newContextFrom(c);
                            req_cont->payload = buf;
                            self->up->upStream(self->up, req_cont);
                            if (!ISALIVE(c))
                            {
                                DISCARD_CONTEXT(c);
                                destroyContext(c);
                                return;
                            }
                        }
                        else if (!BIO_should_retry(cstate->rbio))
                        {
                            // If BIO_should_retry() is false then the cause is an error condition.
                            DISCARD_CONTEXT(c);
                            reuseBuffer(buffer_pools[c->line->tid], buf);
                            goto failed;
                        }
                        else
                        {
                            reuseBuffer(buffer_pools[c->line->tid], buf);
                        }
                    } while (n > 0);

                if (status == SSLSTATUS_FAIL)
                {
                    int x = SSL_get_verify_result(cstate->ssl);
                    printSSLError();
                    DISCARD_CONTEXT(c);
                    goto failed;
                }

                if (!SSL_is_init_finished(cstate->ssl))
                {
                    DISCARD_CONTEXT(c);
                    destroyContext(c);
                    return;
                }
                else
                {
                    LOGD("Tls handshake complete");
                    cstate->handshake_completed = true;
                    context_t *dw_est_ctx = newContextFrom(c);
                    dw_est_ctx->est = true;
                    self->dw->downStream(self->dw, dw_est_ctx);
                    if (!ISALIVE(c))
                    {
                        LOGW("Openssl client: prev node instantly closed the est with fin");
                        DISCARD_CONTEXT(c);
                        destroyContext(c);
                        return;
                    }
                    flush_write_queue(self, c);
                    // queue is flushed and we are done
                    DISCARD_CONTEXT(c);
                    destroyContext(c);
                    return;
                }
            }

            /* The encrypted data is now in the input bio so now we can perform actual
             * read of unencrypted data. */
            // shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
            // shiftl(buf, 8192 / 2);
            // setLen(buf, 0);

            do
            {
                shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                shiftl(buf, 8192 / 2);
                setLen(buf, 0);
                size_t avail = rCap(buf);
                n = SSL_read(cstate->ssl, rawBuf(buf) + bufLen(buf), avail);

                if (n > 0)
                {
                    setLen(buf, n);
                    context_t *data_ctx = newContextFrom(c);
                    data_ctx->payload = buf;
                    self->dw->downStream(self->dw, data_ctx);
                    if (!ISALIVE(c))
                    {
                        DISCARD_CONTEXT(c);
                        destroyContext(c);
                        return;
                    }
                }
                else
                {
                    reuseBuffer(buffer_pools[c->line->tid], buf);
                }

            } while (n > 0);

            status = get_sslstatus(cstate->ssl, n);

            if (status == SSLSTATUS_FAIL)
            {
                DISCARD_CONTEXT(c);
                goto failed;
            }
        }
        // done with socket data
        DISCARD_CONTEXT(c);
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
            destroyContext(c);
    }

    return;

failed:
    context_t *fail_context_up = newFinContext(c->line);
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newFinContext(c->line);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);

    return;
}

static void openSSLUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void openSSLPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c); // TODO : DTLS
}
static void openSSLDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void openSSLPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newOpenSSLClient(node_instance_context_t *instance_info)
{
    oss_client_state_t *state = malloc(sizeof(oss_client_state_t));
    memset(state, 0, sizeof(oss_client_state_t));

    ssl_ctx_opt_t *ssl_param = malloc(sizeof(ssl_ctx_opt_t));
    memset(ssl_param, 0, sizeof(ssl_ctx_opt_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: OpenSSLClient->settings (object field) : The object was empty or invalid.");
        return NULL;
    }

    if (!getStringFromJsonObject(&(state->sni), settings, "sni"))
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty or invalid.");
        return NULL;
    }
    if (strlen(state->sni) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty.");
        return NULL;
    }

    if (!getBoolFromJsonObject(&(state->verify), settings, "verify"))
    {
        state->verify = true;
    }

    if (!getStringFromJsonObject((char **)&(state->alpn), settings, "alpn"))
    {
        LOGF("JSON Error: OpenSSLClient->settings->alpn (string field) : The data was empty or invalid.");
        return NULL;
    }
    if (strlen(state->alpn) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->alpn (string field) : The data was empty.");
        return NULL;
    }

    ssl_param->verify_peer = state->verify ? 1 : 0; // no mtls
    ssl_param->endpoint = SSL_CLIENT;
    // ssl_param->ca_path = "cacert.pem";
    state->ssl_context = ssl_ctx_new(ssl_param);
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
        char alpn_data[];
    } *ossl_alpn = malloc(1 + alpn_len);
    ossl_alpn->len = alpn_len;
    memcpy(&(ossl_alpn->alpn_data[0]), state->alpn, alpn_len);
    SSL_CTX_set_alpn_protos(state->ssl_context, (char *)ossl_alpn, 1 + alpn_len);
    free(ossl_alpn);

    tunnel_t *t = newTunnel();
    t->state = state;

    t->upStream = &openSSLUpStream;
    t->packetUpStream = &openSSLPacketUpStream;
    t->downStream = &openSSLDownStream;
    t->packetDownStream = &openSSLPacketDownStream;
    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiOpenSSLClient(tunnel_t *self, char *msg)
{
    LOGE("openssl-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyOpenSSLClient(tunnel_t *self)
{
    LOGE("openssl-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataOpenSSLClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
