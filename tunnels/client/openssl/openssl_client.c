#include "openssl_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "managers/socket_manager.h"
#include "managers/node_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#define STATE(x) ((oss_client_state_t *)((x)->state))
#define CSTATE(x) ((oss_client_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef void *ssl_ctx_t; ///> SSL_CTX

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
    buffer_pool_t *buffer_pool;
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
        SSL_free(cstate->ssl);                    /* free the SSL object and its BIO's */
        destroyContextQueue(cstate->queue); /* free the SSL object and its BIO's */

        free(cstate);
        CSTATE_MUT(c) = NULL;
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
            if (c->src_io)
                hio_read_stop(c->src_io);
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
                        context_t *send_context = newContext(c->line);
                        send_context->payload = buf;
                        send_context->src_io = c->src_io;
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
            cstate->buffer_pool = buffer_pools[c->line->tid];
            cstate->queue = newContextQueue(cstate->buffer_pool);
            SSL_set_connect_state(cstate->ssl); /* sets ssl to work in client mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            self->up->upStream(self->up, c);
        }
        else if (c->fin)
        {

            cleanup(self, c);
            destroyContext(c);
            self->up->upStream(self->up, c);
        }
    }

    return;

failed:
    context_t *fail_context_up = newContext(c->line);
    fail_context_up->fin = true;
    fail_context_up->src_io = c->src_io;
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newContext(c->line);
    fail_context->fin = true;
    fail_context->src_io = NULL;
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
                n = SSL_do_handshake(cstate->ssl);
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
                            context_t *answer = newContext(c->line);
                            answer->payload = buf;
                            self->dw->downStream(self->dw, answer);
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
                    context_t *dw_est_ctx = newContext(c->line);
                    dw_est_ctx->est = true;
                    dw_est_ctx->src_io = c->src_io;

                    self->dw->downStream(self->dw, dw_est_ctx);
                    if (!ISALIVE(c))
                    {
                        LOGW("Openssl client: prev node instantly closed the est with fin");
                        DISCARD_CONTEXT(c);
                        destroyContext(c);
                        return;
                    }
                }
            }
        }
    }
    else
    {
        if (c->est)
        {
            int n;
            enum sslstatus status;

            if (!cstate->handshake_completed)
            {
                n = SSL_do_handshake(cstate->ssl);
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
                            context_t *handshake_req = newContext(c->line);
                            handshake_req->payload = buf;
                            self->up->upStream(self->up, handshake_req);
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
                    } while (n > 0);

                if (status == SSLSTATUS_FAIL)
                    goto failed;
            }
        }
        else if (c->fin)
        {
            cleanup(self, c);
            self->dw->downStream(self->dw, c);
        }
    }

    return;

failed:
    context_t *fail_context_up = newContext(c->line);
    fail_context_up->fin = true;
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newContext(c->line);
    fail_context->fin = true;
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

typedef struct
{
    const char *crt_file;
    const char *key_file;
    const char *ca_file;
    const char *ca_path;
    short verify_peer;
    short endpoint; // HSSL_client / HSSL_CLIENT
} ssl_ctx_opt_t;

static ssl_ctx_t ssl_ctx_new(ssl_ctx_opt_t *param)
{
    static int s_initialized = 0;
    if (s_initialized == 0)
    {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
#else
        OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);
#endif
        s_initialized = 1;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
#else
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
#endif
    if (ctx == NULL)
        return NULL;
    int mode = SSL_VERIFY_NONE;
    const char *ca_file = NULL;
    const char *ca_path = NULL;
    if (param)
    {
        if (param->ca_file && *param->ca_file)
        {
            ca_file = param->ca_file;
        }
        if (param->ca_path && *param->ca_path)
        {
            ca_path = param->ca_path;
        }
        if (ca_file || ca_path)
        {
            if (!SSL_CTX_load_verify_locations(ctx, ca_file, ca_path))
            {
                fprintf(stderr, "ssl ca_file/ca_path failed!\n");
                goto error;
            }
        }

        if (param->crt_file && *param->crt_file)
        {
            // openssl forces pem for a chained cert!
            if (!SSL_CTX_use_certificate_chain_file(ctx, param->crt_file))
            {
                fprintf(stderr, "ssl crt_file error!\n");
                goto error;
            }
        }

        if (param->key_file && *param->key_file)
        {
            if (!SSL_CTX_use_PrivateKey_file(ctx, param->key_file, SSL_FILETYPE_PEM))
            {
                fprintf(stderr, "ssl key_file error!\n");
                goto error;
            }
            if (!SSL_CTX_check_private_key(ctx))
            {
                fprintf(stderr, "ssl key_file check failed!\n");
                goto error;
            }
        }

        if (param->verify_peer)
        {
            mode = SSL_VERIFY_PEER;
            if (param->endpoint == HSSL_CLIENT)
            {
                mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            }
        }
    }
    if (mode == SSL_VERIFY_PEER && !ca_file && !ca_path)
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }

#ifdef SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    SSL_CTX_set_mode(ctx, SSL_CTX_get_mode(ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
    SSL_CTX_set_verify(ctx, mode, NULL);
    return ctx;
error:
    SSL_CTX_free(ctx);
    return NULL;
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
    ssl_param->endpoint = HSSL_CLIENT;
    state->ssl_context = ssl_ctx_new(ssl_param);
    free(ssl_param);

    if (state->ssl_context == NULL)
    {
        LOGF("OpenSSLClient: Could not create ssl context");
        return NULL;
    }

    SSL_set_tlsext_host_name(state->ssl_context, state->sni);

    size_t alpn_len = strlen(state->alpn);
    struct
    {
        uint8_t len;
        char alpn_data[];
    } *ossl_alpn = malloc(1 + alpn_len);
    ossl_alpn->len = alpn_len;
    memcpy(&(ossl_alpn->alpn_data[0]), state->alpn, alpn_len);
    SSL_CTX_set_alpn_protos(state->ssl_context, (char*)ossl_alpn, 1);
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
