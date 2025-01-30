#include "openssl_server.h"
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

typedef struct
{
    char        *name;
    unsigned int name_length;
    tunnel_t    *next;
} alpn_item_t;

typedef struct oss_server_state_s
{
    ssl_ctx_t   *threadlocal_ssl_context;
    alpn_item_t *alpns;
    unsigned int alpns_length;

    // settings
    tunnel_t *fallback;
    bool      anti_tit; // solve tls in tls using paddings

} oss_server_state_t;

typedef struct oss_server_con_state_s
{

    buffer_stream_t *fallback_buf;
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    bool             handshake_completed;
    bool             fallback_mode;
    bool             fallback_init_sent;
    bool             init_sent;
    int              reply_sent_tit;

    bool fallback_disabled;

} oss_server_con_state_t;

static int onAlpnSelect(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                        unsigned int inlen, void *arg)
{
    (void) ssl;
    assert(inlen != 0);
    oss_server_state_t *state  = arg;
    unsigned int        offset = 0;
    while (offset < inlen)
    {
        // LOGD("client ALPN ->  %.*s", in[offset], &(in[1 + offset]));
        for (int i = 0; i < (int) state->alpns_length; i++)
        {
            if (0 == strncmp((const char *) &(in[1 + offset]), state->alpns[i].name,
                             state->alpns[i].name_length < in[offset] ? state->alpns[i].name_length : in[offset]))
            {
                *out    = &(in[1 + offset]);
                *outlen = in[0 + offset];
                return SSL_TLSEXT_ERR_OK;
            }
        }

        offset = offset + 1 + in[offset];
    }
    return SSL_TLSEXT_ERR_NOACK;
}

enum sslstatus
{
    kSslstatusOk,
    kSslstatusWantIo,
    kSslstatusFail
};

static enum sslstatus getSslstatus(SSL *ssl, int n)
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

static size_t paddingDecisionCb(SSL *ssl, int type, size_t len, void *arg)
{
    (void) ssl;
    (void) type;
    oss_server_con_state_t *cstate = arg;
    // todo (private note)
    if (cstate->reply_sent_tit >= 1 && cstate->reply_sent_tit < 4)
    {
        if (len <= 4096)
        {
            return (size_t) 4096 - len;
        }
        if (len <= 8192)
        {
            return (size_t) 8192 - len;
        }
        if (len <= 16384)
        {
            return (size_t) 16384 - len;
        }
        if (len <= 32768)
        {
            return (size_t) 32768 - len;
        }
    }
    return 0;
}

static void cleanup(tunnel_t *self, context_t *c)
{
    oss_server_con_state_t *cstate = CSTATE(c);
    bufferstreamDestroy(cstate->fallback_buf);
    SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
    memoryFree(cstate);
    CSTATE_DROP(c);
}

static void fallbackWrite(tunnel_t *self, context_t *c)
{
    if (! lineIsAlive(c->line))
    {
        contextDestroy(c);
        return;
    }
    assert(c->payload == NULL); // payload must be consumed
    oss_server_state_t     *state  = TSTATE(self);
    oss_server_con_state_t *cstate = CSTATE(c);

    if (! cstate->fallback_init_sent)
    {
        cstate->fallback_init_sent = true;

        context_t *init_ctx = contextCreateInit(c->line);
        cstate->init_sent   = true;
        state->fallback->upStream(state->fallback, init_ctx);
        if (! lineIsAlive(c->line))
        {
            contextDestroy(c);
            return;
        }
    }
    size_t record_len = bufferstreamLen(cstate->fallback_buf);
    if (record_len == 0)
    {
        contextDestroy(c);
        return;
    }
    c->payload = bufferstreamIdealRead(cstate->fallback_buf);
    state->fallback->upStream(state->fallback, c);
}

static void upStream(tunnel_t *self, context_t *c)
{
    oss_server_state_t     *state  = TSTATE(self);
    oss_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        if (state->fallback != NULL && ! cstate->handshake_completed)
        {
            bufferstreamPush(cstate->fallback_buf, sbufDuplicateByPool(contextGetBufferPool(c),c->payload));
        }

        if (cstate->fallback_mode)
        {
            contextReusePayload(c);
            fallbackWrite(self, c);
            return;
        }
        
        enum sslstatus status;
        int            n;
        unsigned int   len = sbufGetBufLength(c->payload);

        while (len > 0 && lineIsAlive(c->line))
        {
            n = BIO_write(cstate->rbio, sbufGetRawPtr(c->payload), (int) len);

            if (n <= 0)
            {
                /* if BIO write fails, assume unrecoverable */
                contextReusePayload(c);
                goto disconnect;
            }
            sbufShiftRight(c->payload, n);
            len -= n;

            if (! SSL_is_init_finished(cstate->ssl))
            {
                n      = SSL_accept(cstate->ssl);
                status = getSslstatus(cstate->ssl, n);

                /* Did SSL request to write bytes? */
                if (status == kSslstatusWantIo)
                {
                    do
                    {
                        sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                        unsigned int    avail = sbufGetRightCapacity(buf);
                        n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), (int) avail);
                        // assert(-1 == BIO_read(cstate->wbio, sbufGetRawPtr(buf), avail));
                        if (n > 0)
                        {
                            // since then, we should not go to fallback
                            cstate->fallback_disabled = true;

                            sbufSetLength(buf, n);
                            context_t *answer = contextCreateFrom(c);
                            answer->payload   = buf;
                            self->dw->downStream(self->dw, answer);

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
                            contextReusePayload(c);
                            bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                            goto disconnect;
                        }
                        else
                        {
                            bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                        }
                    } while (n > 0);
                }

                if (status == kSslstatusFail)
                {
                    contextReusePayload(c); // payload already buffered
                    printSSLError();
                    if (state->fallback != NULL && ! cstate->fallback_disabled)
                    {
                        cstate->fallback_mode = true;
                        fallbackWrite(self, c);
                        return;
                    }

                    goto disconnect;
                }

                if (! SSL_is_init_finished(cstate->ssl))
                {
                    contextReusePayload(c);
                    contextDestroy(c);
                    return;
                }

                LOGD("OpensslServer: Tls handshake complete");
                cstate->handshake_completed = true;
                bufferstreamEmpty(cstate->fallback_buf);
            }

            /* The encrypted data is now in the input bio so now we can perform actual
             * read of unencrypted data. */

            do
            {
                sbuf_t *buf = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                sbufSetLength(buf, 0);
                unsigned int avail = sbufGetRightCapacity(buf);
                n                  = SSL_read(cstate->ssl, sbufGetMutablePtr(buf), (int) avail);

                if (n > 0)
                {
                    if (UNLIKELY(! cstate->init_sent))
                    {
                        self->up->upStream(self->up, contextCreateInit(c->line));
                        if (! lineIsAlive(c->line))
                        {
                            LOGW("OpensslServer: next node instantly closed the init with fin");
                            contextReusePayload(c);
                            contextDestroy(c);

                            return;
                        }
                        cstate->init_sent = true;
                    }

                    sbufSetLength(buf, n);
                    context_t *data_ctx = contextCreateFrom(c);
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

            } while (n > 0);

            status = getSslstatus(cstate->ssl, n);

            /* Did SSL request to write bytes? This can happen if peer has requested SSL
             * renegotiation. */
            if (status == kSslstatusWantIo)
            {
                do
                {
                    sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                    unsigned int    avail = sbufGetRightCapacity(buf);

                    n = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), (int) avail);
                    if (n > 0)
                    {
                        sbufSetLength(buf, n);
                        context_t *answer = contextCreateFrom(c);
                        answer->payload   = buf;
                        self->dw->downStream(self->dw, answer);
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
                        goto disconnect;
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
                goto disconnect;
            }
        }
        // done with socket data
        contextReusePayload(c);
        contextDestroy(c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = memoryAllocate(sizeof(oss_server_con_state_t));
            memorySet(CSTATE(c), 0, sizeof(oss_server_con_state_t));
            cstate               = CSTATE(c);
            cstate->rbio         = BIO_new(BIO_s_mem());
            cstate->wbio         = BIO_new(BIO_s_mem());
            cstate->ssl          = SSL_new(state->threadlocal_ssl_context[c->line->tid]);
            cstate->fallback_buf = bufferstreamCreate(contextGetBufferPool(c));
            SSL_set_accept_state(cstate->ssl); /* sets ssl to work in server mode. */
            SSL_set_bio(cstate->ssl, cstate->rbio, cstate->wbio);
            if (state->anti_tit)
            {
                if (1 != SSL_set_record_padding_callback(cstate->ssl, paddingDecisionCb))
                {
                    LOGW("OpensslServer: Could not set ssl padding hook");
                }
                SSL_set_record_padding_callback_arg(cstate->ssl, cstate);
            }
            contextDestroy(c);
        }
        else if (c->fin)
        {

            if (cstate->fallback_mode)
            {
                if (cstate->fallback_init_sent)
                {
                    cleanup(self, c);
                    state->fallback->upStream(state->fallback, c);
                }
                else
                {
                    cleanup(self, c);
                    contextDestroy(c);
                }
            }
            else if (cstate->init_sent)
            {
                cleanup(self, c);
                self->up->upStream(self->up, c);
            }
            else
            {
                cleanup(self, c);
                contextDestroy(c);
            }
        }
    }

    return;

disconnect:
    if (cstate->init_sent)
    {
        self->up->upStream(self->up, contextCreateFinFrom(c));
    }

    context_t *fail_context = contextCreateFinFrom(c);
    cleanup(self, c);
    contextDestroy(c);
    self->dw->downStream(self->dw, fail_context);
}

static void downStream(tunnel_t *self, context_t *c)
{
    oss_server_state_t     *state  = TSTATE(self);
    oss_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (state->anti_tit && lineIsAuthenticated(c->line))
        {
            // if (cstate->reply_sent_tit <= 1)
            cstate->reply_sent_tit += 1;
            // this crashes ... openssl said this can be set to null again but seems not :(
            // if (1 != SSL_set_record_padding_callback(cstate->ssl, NULL))
            //     LOGW("OpensslServer: Could not set ssl padding");
        }

        enum sslstatus status;

        if (! cstate->handshake_completed)
        {
            if (cstate->fallback_mode)
            {
                self->dw->downStream(self->dw, c);
                return; // not gona encrypt fall back data
            }

            LOGF("How it is possible to receive data before sending init to upstream?");
            exit(1);
        }
        int len = (int) sbufGetBufLength(c->payload);
        while (len > 0 && lineIsAlive(c->line))
        {

            /*
                todo (test code)
                testing how the filtering behaves if we force protocol client to recevie at least
                2 full chunks before sending anymore data

                sometimes udp or is the underlying protocol so we should not do weird
                kind of stuff to that data otherwise speedtest app may sometimes give up the test :(
                forexample speedtest first packet is sometimes 65 bytes total !
            */
            int sbufConsume = len;
            if ((cstate->reply_sent_tit == 1 && len > 256))
            {
                cstate->reply_sent_tit++;
                sbufConsume = 128;
            }

            int n  = SSL_write(cstate->ssl, sbufGetRawPtr(c->payload), sbufConsume);
            status = getSslstatus(cstate->ssl, n);
            assert(n == sbufConsume);

            if (n > 0)
            {
                /* sbufConsume the waiting bytes that have been used by SSL */
                sbufShiftRight(c->payload, n);
                len -= n;
                /* take the output of the SSL object and queue it for socket write */
                do
                {
                    sbuf_t *buf   = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                    unsigned int    avail = sbufGetRightCapacity(buf);
                    n                     = BIO_read(cstate->wbio, sbufGetMutablePtr(buf), (int) avail);
                    if (n > 0)
                    {
                        sbufSetLength(buf, n);
                        context_t *dw_context = contextCreateFrom(c);
                        dw_context->payload   = buf;
                        self->dw->downStream(self->dw, dw_context);
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
                        goto disconnect;
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
                goto disconnect;
            }

            if (n == 0)
            {
                break;
            }
        }
        assert(sbufGetBufLength(c->payload) == 0);
        contextReusePayload(c);
        contextDestroy(c);

        return;
    }

    if (c->est)
    {
        self->dw->downStream(self->dw, c);
        return;
    }
    if (c->fin)
    {
        cleanup(self, c);
        self->dw->downStream(self->dw, c);
    }

    return;

disconnect: {
    context_t *fail_context_up = contextCreateFinFrom(c);
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = contextCreateFinFrom(c);
    cleanup(self, c);
    contextDestroy(c);
    self->dw->downStream(self->dw, fail_context);
}
}

tunnel_t *newOpenSSLServer(node_instance_context_t *instance_info)
{
    oss_server_state_t *state = memoryAllocate(sizeof(oss_server_state_t));
    memorySet(state, 0, sizeof(oss_server_state_t));

    state->threadlocal_ssl_context = memoryAllocate(sizeof(ssl_ctx_t) * getWorkersCount());

    ssl_ctx_opt_t *ssl_param = memoryAllocate(sizeof(ssl_ctx_opt_t));
    memorySet(ssl_param, 0, sizeof(ssl_ctx_opt_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: OpenSSLServer->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject((char **) &(ssl_param->crt_file), settings, "cert-file"))
    {
        LOGF("JSON Error: OpenSSLServer->settings->cert-file (string field) : The data was empty or invalid");
        return NULL;
    }
    if (strlen(ssl_param->crt_file) == 0)
    {
        LOGF("JSON Error: OpenSSLServer->settings->cert-file (string field) : The data was empty");
        return NULL;
    }

    if (! getStringFromJsonObject((char **) &(ssl_param->key_file), settings, "key-file"))
    {
        LOGF("JSON Error: OpenSSLServer->settings->key-file (string field) : The data was empty or invalid");
        return NULL;
    }
    if (strlen(ssl_param->key_file) == 0)
    {
        LOGF("JSON Error: OpenSSLServer->settings->key-file (string field) : The data was empty");
        return NULL;
    }

    const cJSON *aplns_array = cJSON_GetObjectItemCaseSensitive(settings, "alpns");
    if (cJSON_IsArray(aplns_array))
    {
        size_t len   = cJSON_GetArraySize(aplns_array);
        state->alpns = memoryAllocate(len * sizeof(alpn_item_t));
        memorySet(state->alpns, 0, len * sizeof(alpn_item_t));

        int          i = 0;
        const cJSON *alpn_item;

        cJSON_ArrayForEach(alpn_item, aplns_array)
        {
            if (cJSON_IsObject(alpn_item))
            {
                if (! getStringFromJsonObject(&(state->alpns[i].name), alpn_item, "value"))
                {
                    LOGF("JSON Error: OpensslServer->settigs->alpns[%d]->value (object field) : The data was empty or "
                         "invalid",
                         i);
                    return NULL;
                }
                state->alpns[i].name_length = strlen(state->alpns[i].name);
                // todo route next parse
                i++;
            }
        }
        state->alpns_length = i;
    }

    char *fallback_node = NULL;
    if (! getStringFromJsonObject(&fallback_node, settings, "fallback"))
    {
        LOGW("OpensslServer: no fallback provided in json, not recommended");
    }
    else
    {
        hash_t  hash_next = calcHashBytes(fallback_node, strlen(fallback_node));
        node_t *next_node = nodemanagerGetNode(instance_info->node_manager_config, hash_next);
        if (next_node == NULL)
        {
            LOGF("OpensslServer: fallback node not found");
            exit(1);
        }

        if (next_node->instance == NULL)
        {
            nodemanagerRunNode(instance_info->node_manager_config, next_node, instance_info->chain_index + 1);
        }

        state->fallback = next_node->instance;
    }
    memoryFree(fallback_node);
    getBoolFromJsonObjectOrDefault(&(state->anti_tit), settings, "anti-tls-in-tls", false);

    ssl_param->verify_peer = 0; // no mtls
    ssl_param->endpoint    = kSslServer;

    for (unsigned int i = 0; i < getWorkersCount(); i++)
    {
        state->threadlocal_ssl_context[i] = sslCtxNew(ssl_param);
        if (state->threadlocal_ssl_context[i] == NULL)
        {
            LOGF("OpensslServer: Could not create ssl context");
            return NULL;
        }

        SSL_CTX_set_alpn_select_cb(state->threadlocal_ssl_context[i], onAlpnSelect, state);
    }
    // int brotli_alg = TLSEXT_comp_cert_brotli;
    // SSL_set1_cert_comp_preference(state->ssl_context,&brotli_alg,1);
    // SSL_compress_certs(state->ssl_context,TLSEXT_comp_cert_brotli);

    memoryFree((char *) ssl_param->crt_file);
    memoryFree((char *) ssl_param->key_file);
    memoryFree(ssl_param);

    tunnel_t *t = tunnelCreate();
    t->state    = state;
    if (state->fallback != NULL)
    {
        tunnelBindDown(t, state->fallback);
    }
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiOpenSSLServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyOpenSSLServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataOpenSSLServer(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
