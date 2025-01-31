#include "reality_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "context_queue.h"
#include "loggers/network_logger.h"
#include "openssl_globals.h"
#include "reality_helpers.h"
#include "tunnel.h"

#include "utils/jsonutils.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

typedef struct reality_client_state_s
{

    ssl_ctx_t       *threadlocal_ssl_context;
    EVP_MD_CTX     **threadlocal_sign_context;
    EVP_CIPHER_CTX **threadlocal_cipher_context;

    // settings
    uint8_t hashes[EVP_MAX_MD_SIZE];
    char    context_password[kSignPasswordLen];
    char   *alpn;
    char   *sni;
    char   *password;
    bool    verify;
    int     password_length;

} reality_client_state_t;

typedef struct reality_client_con_state_s
{
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    EVP_MD          *msg_digest;
    EVP_PKEY        *sign_key;
    EVP_MD_CTX      *sign_context;
    EVP_CIPHER_CTX  *cipher_context;
    buffer_stream_t *read_stream;
    context_queue_t *queue;
    bool             handshake_completed;

} reality_client_con_state_t;

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
    reality_client_con_state_t *cstate = CSTATE(c);
    if (cstate->handshake_completed)
    {
        bufferstreamDestroy(cstate->read_stream);
    }
    // EVP_CIPHER_CTX_free(cstate->cipher_context);
    // EVP_MD_CTX_free(cstate->sign_context);
    EVP_MD_free(cstate->msg_digest);
    EVP_PKEY_free(cstate->sign_key);

    SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
    contextqueueDestory(cstate->queue);

    memoryFree(cstate);
    CSTATE_DROP(c);
}

static void flushWriteQueue(tunnel_t *self, context_t *c)
{
    reality_client_con_state_t *cstate = CSTATE(c);

    while (lineIsAlive(c->line) && contextqueueLen(cstate->queue) > 0)
    {
        self->upStream(self, contextqueuePop(cstate->queue));
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    reality_client_state_t *state = TSTATE(self);

    if (c->payload != NULL)
    {
        reality_client_con_state_t *cstate = CSTATE(c);

        if (! cstate->handshake_completed)
        {
            contextqueuePush(cstate->queue, c);
            return;
        }
        // todo (research) about encapsulation order and safety, CMAC HMAC
        sbuf_t *buf = c->payload;
        c->payload          = NULL;

        const unsigned int chunk_size = (kMaxSSLChunkSize - (kSignLen + (2 * kEncryptionBlockSize) + kIVlen));

        if (sbufGetBufLength(buf) < chunk_size)
        {

            buf = genericEncrypt(buf, cstate->cipher_context, state->context_password, contextGetBufferPool(c));
            signMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
            appendTlsHeader(buf);
            assert(sbufGetBufLength(buf) % 16 == 5);
            c->payload = buf;

            self->up->upStream(self->up, c);
        }
        else
        {
            while (sbufGetBufLength(buf) > 0 && lineIsAlive(c->line))
            {
                const uint16_t  remain = (uint16_t) min(sbufGetBufLength(buf), chunk_size);
                sbuf_t *chunk  = bufferpoolGetLargeBuffer(contextGetBufferPool(c));
                chunk = sbufMoveTo( chunk,buf, remain);

                chunk = genericEncrypt(chunk, cstate->cipher_context, state->context_password, contextGetBufferPool(c));
                signMessage(chunk, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
                appendTlsHeader(chunk);
                context_t *cout = contextCreateFrom(c);
                cout->payload   = chunk;
                assert(sbufGetBufLength(chunk) % 16 == 5);
                self->up->upStream(self->up, cout);
            }
            bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
            contextDestroy(c);
        }
    }
    else
    {
        if (c->init)
        {
            reality_client_con_state_t *cstate = memoryAllocate(sizeof(reality_client_con_state_t));
            memorySet(cstate, 0, sizeof(reality_client_con_state_t));
            CSTATE_MUT(c)          = cstate;
            cstate->rbio           = BIO_new(BIO_s_mem());
            cstate->wbio           = BIO_new(BIO_s_mem());
            cstate->ssl            = SSL_new(state->threadlocal_ssl_context[getWID()]);
            cstate->cipher_context = state->threadlocal_cipher_context[getWID()];
            cstate->sign_context   = state->threadlocal_sign_context[getWID()];
            cstate->queue          = contextqueueCreate();
            cstate->msg_digest     = (EVP_MD *) EVP_get_digestbynid(MSG_DIGEST_ALG);
            int sk_size            = EVP_MD_size(cstate->msg_digest);
            cstate->sign_key       = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, state->hashes, sk_size);

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
    reality_client_state_t     *state  = TSTATE(self);
    reality_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        if (cstate->handshake_completed)
        {
            bufferStreamPushContextPayload(cstate->read_stream, c);
            uint8_t tls_header[1 + 2 + 2];
            while (lineIsAlive(c->line) && bufferstreamLen(cstate->read_stream) >= kTLSHeaderlen)
            {
                bufferstreamViewBytesAt(cstate->read_stream, 0, tls_header, kTLSHeaderlen);
                uint16_t length = ntohs(*(uint16_t *) (tls_header + 3));
                if ((int) bufferstreamLen(cstate->read_stream) >= kTLSHeaderlen + length)
                {
                    sbuf_t *buf = bufferstreamReadExact(cstate->read_stream, kTLSHeaderlen + length);
                    bool            is_tls_applicationdata = ((uint8_t *) sbufGetRawPtr(buf))[0] == kTLS12ApplicationData;
                    uint16_t        tls_ver_b;
                    memoryCopy(&tls_ver_b, ((uint8_t *) sbufGetRawPtr(buf)) + 1, sizeof(uint16_t));
                    bool is_tls_33 = tls_ver_b == kTLSVersion12;

                    sbufShiftRight(buf, kTLSHeaderlen);

                    if (! verifyMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key) ||
                        ! is_tls_applicationdata || ! is_tls_33)
                    {
                        LOGE("RealityClient: verifyMessage failed");
                        bufferpoolResuesBuffer(contextGetBufferPool(c), buf);
                        goto failed;
                    }

                    buf = genericDecrypt(buf, cstate->cipher_context, state->context_password, contextGetBufferPool(c));

                    context_t *plain_data_ctx = contextCreateFrom(c);
                    plain_data_ctx->payload   = buf;
                    self->dw->downStream(self->dw, plain_data_ctx);
                }
                else
                {
                    break;
                }
            }
            contextDestroy(c);
            return;
        }

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

                if (SSL_is_init_finished(cstate->ssl))
                {
                    LOGD("RealityClient: Tls handshake complete");

                    cstate->handshake_completed = true;
                    cstate->read_stream         = bufferstreamCreate(contextGetBufferPool(c));

                    flushWriteQueue(self, c);

                    context_t *dw_est_ctx = contextCreateFrom(c);
                    dw_est_ctx->est       = true;
                    self->dw->downStream(self->dw, dw_est_ctx);
                }
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

tunnel_t *newRealityClient(node_instance_context_t *instance_info)
{
    reality_client_state_t *state = memoryAllocate(sizeof(reality_client_state_t));
    memorySet(state, 0, sizeof(reality_client_state_t));

    state->threadlocal_ssl_context    = memoryAllocate(sizeof(ssl_ctx_t) * getWorkersCount());
    state->threadlocal_cipher_context = memoryAllocate(sizeof(EVP_CIPHER_CTX *) * getWorkersCount());
    state->threadlocal_sign_context   = memoryAllocate(sizeof(EVP_MD_CTX *) * getWorkersCount());

    ssl_ctx_opt_t *ssl_param = memoryAllocate(sizeof(ssl_ctx_opt_t));
    memorySet(ssl_param, 0, sizeof(ssl_ctx_opt_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: RealityClient->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->sni), settings, "sni"))
    {
        LOGF("JSON Error: RealityClient->settings->sni (string field) : The data was empty or invalid");
        return NULL;
    }
    if (strlen(state->sni) == 0)
    {
        LOGF("JSON Error: RealityClient->settings->sni (string field) : The data was empty");
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&(state->verify), settings, "verify", true);

    getStringFromJsonObjectOrDefault(&(state->alpn), settings, "alpn", "http/1.1");

    if (! getStringFromJsonObject(&(state->password), settings, "password"))
    {
        LOGF("JSON Error: RealityClient->settings->password (string field) : The data was empty or invalid");
        return NULL;
    }

    state->password_length = (int) strlen(state->password);
    if (state->password_length < 3)
    {
        LOGF("JSON Error: RealityClient->settings->password (string field) : password is too short");
        return NULL;
    }
    // memorySet already made buff 0
    memoryCopy(state->context_password, state->password, state->password_length);

    if (EVP_MAX_MD_SIZE % sizeof(uint64_t) != 0)
    {
        LOGF("Assert Error: RealityClient-> EVP_MAX_MD_SIZE not a multiple of 8");
        return NULL;
    }

    uint64_t *p64 = (uint64_t *) state->hashes;
    p64[0]        = calcHashBytes(state->password, strlen(state->password));
    for (int i = 1; i < (int) (EVP_MAX_MD_SIZE / sizeof(uint64_t)); i++)
    {
        p64[i] = p64[i - 1];
    }

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

        state->threadlocal_cipher_context[i] = EVP_CIPHER_CTX_new();
        state->threadlocal_sign_context[i]   = EVP_MD_CTX_create();
    }

    memoryFree(ssl_param);
    memoryFree(ossl_alpn);

    tunnel_t *t   = tunnelCreate();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiRealityClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyRealityClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataRealityClient(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
