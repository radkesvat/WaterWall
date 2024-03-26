#include "wolfssl_server.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "managers/node_manager.h"
#include "managers/socket_manager.h"
#include "loggers/network_logger.h"
#include "utils/jsonutils.h"
#include "wolfssl_globals.h"

#include <wolfssl/options.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/ssl.h>

#define STATE(x) ((wssl_server_state_t *)((x)->state))
#define CSTATE(x) ((wssl_server_con_state_t *)((((x)->line->chains_state)[self->chain_index])))
#define CSTATE_MUT(x) ((x)->line->chains_state)[self->chain_index]
#define ISALIVE(x) (CSTATE(x) != NULL)

typedef struct wssl_server_state_s
{

    ssl_ctx_t ssl_context;
    // settings
    char *alpns;
    tunnel_t *fallback;
    int fallback_delay;

} wssl_server_state_t;

typedef struct wssl_server_con_state_s
{

    bool handshake_completed;

    bool fallback;
    bool fallback_init_sent;
    bool fallback_first_sent;
    buffer_stream_t *fallback_buf;
    line_t *fallback_line;
    // htimer_t *fallback_timer;

    SSL *ssl;

    BIO *rbio;
    BIO *wbio;

    bool first_sent;
    bool init_sent;

} wssl_server_con_state_t;

struct timer_eventdata
{
    tunnel_t *self;
    context_t *c;
};

static int on_alpn_select(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg)
{
    assert(inlen != 0);

    unsigned int offset = 0;
    int http_level = 0;

    while (offset < inlen)
    {
        // LOGD("WolfsslServer: client ALPN ->  %.*s", in[offset], &(in[1 + offset]));
        if (in[offset] == 2 && http_level < 2)
        {
            if (strncmp(&(in[1 + offset]), "h2", 2) == 0)
            {
                http_level = 2;
                *out = &(in[1 + offset]);
                *outlen = in[0 + offset];
            }
        }
        else if (in[offset] == 8 && http_level < 1)
        {
            if (strncmp(&(in[1 + offset]), "http/1.1", 8) == 0)
            {
                http_level = 1;
                *out = &(in[1 + offset]);
                *outlen = in[0 + offset];
            }
        }

        offset = offset + 1 + in[offset];
    }
    // TODO alpn paths
    // TODO check if nginx behaviour is different
    if (http_level > 0)
    {
        return SSL_TLSEXT_ERR_OK;
    }
    else
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    // selecting first alpn -_-
    // *out = in + 1;
    // *outlen = in[0];
    // return SSL_TLSEXT_ERR_OK;

    return SSL_TLSEXT_ERR_NOACK;
}

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
    wssl_server_con_state_t *cstate = CSTATE(c);
    if (cstate != NULL)
    {
        destroyBufferStream(cstate->fallback_buf);
        SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
}

static struct timer_eventdata *newTimerData(tunnel_t *self, context_t *c)
{
    struct timer_eventdata *result = malloc(sizeof(struct timer_eventdata));
    result->self = self;
    result->c = c;
    return result;
}

static void fallback_write(tunnel_t *self, context_t *c)
{
    if (!ISALIVE(c))
    {
        destroyContext(c);
        return;
    }
    assert(c->payload == NULL); // payload must be consumed
    wssl_server_state_t *state = STATE(self);
    wssl_server_con_state_t *cstate = CSTATE(c);

    if (!cstate->fallback_init_sent)
    {
        cstate->fallback_init_sent = true;

        context_t *init_ctx = newInitContext(c->line);
        init_ctx->src_io = c->src_io;
        cstate->init_sent = true;
        state->fallback->upStream(state->fallback, init_ctx);
        if (!ISALIVE(c))
        {
            destroyContext(c);
            return;
        }
    }
    size_t record_len = bufferStreamLen(cstate->fallback_buf);
    if (record_len == 0)
        return;
    if (!cstate->fallback_first_sent)
    {
        c->first = true;
        cstate->fallback_first_sent = true;
    }

    c->payload = bufferStreamRead(cstate->fallback_buf, record_len);
    state->fallback->upStream(state->fallback, c);
}
static void on_fallback_timer(htimer_t *timer)
{
    struct timer_eventdata *data = hevent_userdata(timer);
    fallback_write(data->self, data->c);
    htimer_del(timer);
    free(data);
}

static inline void upStream(tunnel_t *self, context_t *c)
{
    wssl_server_state_t *state = STATE(self);

    if (c->payload != NULL)
    {
        wssl_server_con_state_t *cstate = CSTATE(c);

        if (!cstate->handshake_completed)
        {
            bufferStreamPush(cstate->fallback_buf, newShadowShiftBuffer(c->payload));
        }
        if (cstate->fallback)
        {
            DISCARD_CONTEXT(c);
            if (state->fallback_delay <= 0)
                fallback_write(self, c);
            else
            {
                htimer_t *fallback_timer = htimer_add(c->line->loop, on_fallback_timer, state->fallback_delay, 1);
                hevent_set_userdata(fallback_timer, newTimerData(self, c));
            }

            return;
        }
        enum sslstatus status;
        int n;
        size_t len = bufLen(c->payload);

        while (len > 0)
        {
            n = BIO_write(cstate->rbio, rawBuf(c->payload), len);

            if (n <= 0)
            {
                /* if BIO write fails, assume unrecoverable */
                DISCARD_CONTEXT(c);
                goto disconnect;
            }
            shiftr(c->payload, n);
            len -= n;

            if (!SSL_is_init_finished(cstate->ssl))
            {
                n = SSL_accept(cstate->ssl);
                status = get_sslstatus(cstate->ssl, n);

                /* Did SSL request to write bytes? */
                if (status == SSLSTATUS_WANT_IO)
                    do
                    {
                        shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                        size_t avail = rCap(buf);
                        n = BIO_read(cstate->wbio, rawBuf(buf), avail);
                        // assert(-1 == BIO_read(cstate->wbio, rawBuf(buf), avail));
                        if (n > 0)
                        {
                            setLen(buf, n);
                            context_t *answer = newContextFrom(c);
                            answer->payload = buf;
                            self->dw->downStream(self->dw, answer);
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
                            DISCARD_CONTEXT(c);
                            reuseBuffer(buffer_pools[c->line->tid], buf);
                            goto disconnect;
                        }
                        else
                        {
                            reuseBuffer(buffer_pools[c->line->tid], buf);
                        }
                    } while (n > 0);

                if (status == SSLSTATUS_FAIL)
                {
                    DISCARD_CONTEXT(c); // payload already buffered
                    printSSLError();
                    if (state->fallback != NULL)
                    {
                        cstate->fallback = true;
                        if (state->fallback_delay <= 0)
                            fallback_write(self, c);
                        else
                        {
                            htimer_t *fallback_timer = htimer_add(c->line->loop, on_fallback_timer, state->fallback_delay, 1);
                            hevent_set_userdata(fallback_timer, newTimerData(self, c));
                        }
                        return;
                    }
                    else
                        goto disconnect;
                }

                if (!SSL_is_init_finished(cstate->ssl))
                {
                    DISCARD_CONTEXT(c);
                    destroyContext(c);
                    return;
                }
                else
                {
                    LOGD("WolfsslServer: Tls handshake complete");
                    cstate->handshake_completed = true;
                    context_t *up_init_ctx = newInitContext(c->line);
                    up_init_ctx->src_io = c->src_io;
                    self->up->upStream(self->up, up_init_ctx);
                    if (!ISALIVE(c))
                    {
                        LOGW("WolfsslServer: next node instantly closed the init with fin");
                        DISCARD_CONTEXT(c);
                        destroyContext(c);

                        return;
                    }
                    cstate->init_sent = true;
                }
            }

            /* The encrypted data is now in the input bio so now we can perform actual
             * read of unencrypted data. */

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
                    data_ctx->src_io = c->src_io;
                    if (!(cstate->first_sent))
                    {
                        data_ctx->first = true;
                        cstate->first_sent = true;
                    }
                    self->up->upStream(self->up, data_ctx);
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

            /* Did SSL request to write bytes? This can happen if peer has requested SSL
             * renegotiation. */
            if (status == SSLSTATUS_WANT_IO)
                do
                {
                    shift_buffer_t *buf = popBuffer(buffer_pools[c->line->tid]);
                    size_t avail = rCap(buf);

                    n = BIO_read(cstate->wbio, rawBuf(buf), avail);
                    if (n > 0)
                    {
                        setLen(buf, n);
                        context_t *answer = newContextFrom(c);
                        answer->payload = buf;
                        self->dw->downStream(self->dw, answer);
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
                        destroyContext(c);

                        goto failed_after_establishment;
                    }
                    else
                    {
                        reuseBuffer(buffer_pools[c->line->tid], buf);
                    }
                } while (n > 0);

            if (status == SSLSTATUS_FAIL)
            {
                DISCARD_CONTEXT(c);
                goto failed_after_establishment;
            }
        }
        // done with socket data
        DISCARD_CONTEXT(c);
        destroyContext(c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(wssl_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(wssl_server_con_state_t));
            wssl_server_con_state_t *cstate = CSTATE(c);
            cstate->rbio = BIO_new(BIO_s_mem());
            cstate->wbio = BIO_new(BIO_s_mem());
            cstate->ssl = SSL_new(state->ssl_context);
            cstate->fallback_buf = newBufferStream(buffer_pools[c->line->tid]);
            SSL_set_accept_state(cstate->ssl); /* sets ssl to work in server mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            destroyContext(c);
        }
        else if (c->fin)
        {

            if (CSTATE(c)->fallback)
            {
                if (CSTATE(c)->fallback_init_sent)
                {
                    cleanup(self, c);
                    state->fallback->upStream(state->fallback, c);
                }
                else
                    cleanup(self, c);
            }
            else if (CSTATE(c)->init_sent)
            {
                cleanup(self, c);
                self->up->upStream(self->up, c);
            }
            else
            {
                cleanup(self, c);
                destroyContext(c);
            }
        }
    }

    return;

failed_after_establishment:;
    context_t *fail_context_up = newFinContext(c->line);
    fail_context_up->src_io = c->src_io;
    self->up->upStream(self->up, fail_context_up);

disconnect:;
    context_t *fail_context = newFinContext(c->line);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
    return;
}

static inline void downStream(tunnel_t *self, context_t *c)
{
    wssl_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        // self->dw->downStream(self->dw, ctx);
        // char buf[DEFAULT_BUF_SIZE];
        enum sslstatus status;

        if (!cstate->handshake_completed)
        {
            if (cstate->fallback)
            {
                self->dw->downStream(self->dw, c);
                return; // not gona encrypt fall back data
            }
            else
            {
                LOGF("How it is possible to receive data before sending init to upstream?");
                exit(1);
            }
        }
        size_t len = bufLen(c->payload);
        while (len)
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
                        context_t *dw_context = newContextFrom(c);
                        dw_context->payload = buf;
                        dw_context->src_io = c->src_io;
                        self->dw->downStream(self->dw, dw_context);
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
                        goto failed_after_establishment;
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
                goto failed_after_establishment;
            }

            if (n == 0)
                break;
        }
        assert(bufLen(c->payload) == 0);
        DISCARD_CONTEXT(c);
        destroyContext(c);

        return;
    }
    else
    {
        if (c->est)
        {
            self->dw->downStream(self->dw, c);
            return;
        }
        else if (c->fin)
        {
            cleanup(self, c);
            self->dw->downStream(self->dw, c);
        }
    }
    return;

failed_after_establishment:;
    context_t *fail_context_up = newFinContext(c->line);
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newFinContext(c->line);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);

    return;
}

static void wolfSSLUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c);
}
static void wolfSSLPacketUpStream(tunnel_t *self, context_t *c)
{
    upStream(self, c); // TODO : DTLS
}
static void wolfSSLDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}
static void wolfSSLPacketDownStream(tunnel_t *self, context_t *c)
{
    downStream(self, c);
}

tunnel_t *newWolfSSLServer(node_instance_context_t *instance_info)
{
    wssl_server_state_t *state = malloc(sizeof(wssl_server_state_t));
    memset(state, 0, sizeof(wssl_server_state_t));

    ssl_ctx_opt_t *ssl_param = malloc(sizeof(ssl_ctx_opt_t));
    memset(ssl_param, 0, sizeof(ssl_ctx_opt_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (!(cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: WolfSSLServer->settings (object field) : The object was empty or invalid.");
        return NULL;
    }

    if (!getStringFromJsonObject((char **)&(ssl_param->crt_file), settings, "cert-file"))
    {
        LOGF("JSON Error: WolfSSLServer->settings->cert-file (string field) : The data was empty or invalid.");
        return NULL;
    }
    if (strlen(ssl_param->crt_file) == 0)
    {
        LOGF("JSON Error: WolfSSLServer->settings->cert-file (string field) : The data was empty.");
        return NULL;
    }

    if (!getStringFromJsonObject((char **)&(ssl_param->key_file), settings, "key-file"))
    {
        LOGF("JSON Error: WolfSSLServer->settings->key-file (string field) : The data was empty or invalid.");
        return NULL;
    }
    if (strlen(ssl_param->key_file) == 0)
    {
        LOGF("JSON Error: WolfSSLServer->settings->key-file (string field) : The data was empty.");
        return NULL;
    }

    char *fallback_node = NULL;
    if (!getStringFromJsonObject(&fallback_node, settings, "fallback"))
    {
        LOGW("WolfsslServer: no fallback provided in json, not recommended");
    }
    else
    {
        getIntFromJsonObject(&(state->fallback_delay), settings, "fallback-intence-delay");
        if (state->fallback_delay < 0)
            state->fallback_delay = 0;

        LOGD("WolfsslServer: accessing fallback node");

        hash_t hash_next = calcHashLen(fallback_node, strlen(fallback_node));
        node_t *next_node = getNode(hash_next);
        if (next_node == NULL)
        {
            LOGF("WolfsslServer: fallback node not found");
            exit(1);
        }

        if (next_node->instance == NULL)
        {
            runNode(next_node, instance_info->chain_index + 1);
        }

        state->fallback = next_node->instance;
    }
    free(fallback_node);

    ssl_param->verify_peer = 0; // no mtls
    ssl_param->endpoint = SSL_SERVER;
    state->ssl_context = ssl_ctx_new(ssl_param);
    // int brotli_alg = TLSEXT_comp_cert_brotli;
    // SSL_set1_cert_comp_preference(state->ssl_context,&brotli_alg,1);
    // SSL_compress_certs(state->ssl_context,TLSEXT_comp_cert_brotli);

    free((char *)ssl_param->crt_file);
    free((char *)ssl_param->key_file);
    free(ssl_param);

    if (state->ssl_context == NULL)
    {
        LOGF("WolfsslServer: Could not create ssl context");
        return NULL;
    }

    SSL_CTX_set_alpn_select_cb(state->ssl_context, on_alpn_select, NULL);

    tunnel_t *t = newTunnel();
    t->state = state;
    if (state->fallback != NULL)
    {
        state->fallback->dw = t;
    }
    t->upStream = &wolfSSLUpStream;
    t->packetUpStream = &wolfSSLPacketUpStream;
    t->downStream = &wolfSSLDownStream;
    t->packetDownStream = &wolfSSLPacketDownStream;
    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiWolfSSLServer(tunnel_t *self, char *msg)
{
    LOGE("wolfssl-server API NOT IMPLEMENTED");
    return (api_result_t){0}; // TODO
}

tunnel_t *destroyWolfSSLServer(tunnel_t *self)
{
    LOGE("wolfssl-server DESTROY NOT IMPLEMENTED"); // TODO
    return NULL;
}

tunnel_metadata_t getMetadataWolfSSLServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
