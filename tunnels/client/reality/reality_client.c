#include "reality_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "context_queue.h"
#include "loggers/network_logger.h"
#include "openssl_globals.h"
#include "reality_helpers.h"
#include "tunnel.h"
#include "utils/hashutils.h"
#include "utils/jsonutils.h"
#include "utils/mathutils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

typedef struct reality_client_state_s
{

    ssl_ctx_t ssl_context;
    // settings
    char   *alpn;
    char   *sni;
    char   *password;
    int     password_length;
    bool    verify;
    uint8_t hashes[EVP_MAX_MD_SIZE];
    char    context_password[kSignPasswordLen];

} reality_client_state_t;

typedef struct reality_client_con_state_s
{
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    EVP_MD          *msg_digest;
    EVP_PKEY        *sign_key;
    EVP_MD_CTX      *sign_context;
    EVP_CIPHER_CTX  *encryption_context;
    EVP_CIPHER_CTX  *decryption_context;
    buffer_stream_t *read_stream;
    context_queue_t *queue;
    bool             handshake_completed;
    bool             first_sent;

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
    if (cstate != NULL)
    {
        if (cstate->handshake_completed)
        {
            destroyBufferStream(cstate->read_stream);
        }
        EVP_CIPHER_CTX_free(cstate->encryption_context);
        EVP_CIPHER_CTX_free(cstate->decryption_context);
        EVP_MD_CTX_free(cstate->sign_context);
        EVP_MD_free(cstate->msg_digest);
        EVP_PKEY_free(cstate->sign_key);

        SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
        destroyContextQueue(cstate->queue);

        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
}

static void flushWriteQueue(tunnel_t *self, context_t *c)
{
    reality_client_con_state_t *cstate = CSTATE(c);

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
    reality_client_state_t *state = STATE(self);

    if (c->payload != NULL)
    {
        reality_client_con_state_t *cstate = CSTATE(c);

        if (! cstate->handshake_completed)
        {
            contextQueuePush(cstate->queue, c);
            return;
        }
        // todo (research) about encapsulation order and safety, CMAC HMAC
        shift_buffer_t *buf = c->payload;
        c->payload          = NULL;

        const int chunk_size = ((1 << 16) - (kSignLen + (2 * kEncryptionBlockSize) + kIVlen));

        if (bufLen(buf) < chunk_size)
        {

            buf = genericEncrypt(buf, cstate->encryption_context, state->context_password, getContextBufferPool(c));
            signMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
            appendTlsHeader(buf);
            assert(bufLen(buf) % 16 == 5);
            c->payload = buf;

            self->up->upStream(self->up, c);
        }
        else
        {
            while (bufLen(buf) > 0)
            {
                const uint16_t  remain = (uint16_t) min(bufLen(buf), chunk_size);
                shift_buffer_t *chunk  = shallowSliceBuffer(buf, remain);
                chunk =
                    genericEncrypt(chunk, cstate->encryption_context, state->context_password, getContextBufferPool(c));
                signMessage(chunk, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
                appendTlsHeader(chunk);
                context_t *cout = newContextFrom(c);
                cout->payload   = chunk;
                assert(bufLen(chunk) % 16 == 5);
                self->up->upStream(self->up, cout);
            }
            reuseBuffer(getContextBufferPool(c), buf);
            destroyContext(c);
        }
    }
    else
    {
        if (c->init)
        {
            reality_client_con_state_t *cstate = malloc(sizeof(reality_client_con_state_t));
            memset(cstate, 0, sizeof(reality_client_con_state_t));
            CSTATE_MUT(c)              = cstate;
            cstate->rbio               = BIO_new(BIO_s_mem());
            cstate->wbio               = BIO_new(BIO_s_mem());
            cstate->ssl                = SSL_new(state->ssl_context);
            cstate->queue              = newContextQueue(getContextBufferPool(c));
            cstate->encryption_context = EVP_CIPHER_CTX_new();
            cstate->decryption_context = EVP_CIPHER_CTX_new();
            cstate->sign_context       = EVP_MD_CTX_create();
            cstate->msg_digest         = (EVP_MD *) EVP_get_digestbyname(MSG_DIGEST_ALG);
            int sk_size                = EVP_MD_size(cstate->msg_digest);
            cstate->sign_key           = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, state->hashes, sk_size);

            EVP_DigestInit_ex(cstate->sign_context, cstate->msg_digest, NULL);

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
    reality_client_state_t     *state  = STATE(self);
    reality_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        if (cstate->handshake_completed)
        {
            bufferStreamPush(cstate->read_stream, c->payload);
            c->payload = NULL;
            uint8_t tls_header[1 + 2 + 2];
            while (bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen)
            {
                bufferStreamViewBytesAt(cstate->read_stream, 0, tls_header, kTLSHeaderlen);
                uint16_t length = *(uint16_t *) (tls_header + 3);
                if (bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen + length)
                {
                    shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, kTLSHeaderlen + length);
                    shiftr(buf, kTLSHeaderlen);

                    if (! verifyMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key))
                    {
                        LOGE("RealityClient: verifyMessage failed");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto failed;
                    }

                    buf = genericDecrypt(buf, cstate->decryption_context, state->context_password,
                                         getContextBufferPool(c));

                    context_t *plain_data_ctx = newContextFrom(c);
                    plain_data_ctx->payload   = buf;
                    self->dw->downStream(self->dw, plain_data_ctx);
                }
                else
                {
                    break;
                }
            }
            destroyContext(c);
            return;
        }

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

                if (SSL_is_init_finished(cstate->ssl))
                {
                    LOGD("RealityClient: Tls handshake complete");
                    reality_client_state_t *state = STATE(self);

                    cstate->handshake_completed = true;
                    cstate->read_stream         = newBufferStream(getContextBufferPool(c));

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
                }
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

tunnel_t *newRealityClient(node_instance_context_t *instance_info)
{
    reality_client_state_t *state = malloc(sizeof(reality_client_state_t));
    memset(state, 0, sizeof(reality_client_state_t));

    ssl_ctx_opt_t *ssl_param = malloc(sizeof(ssl_ctx_opt_t));
    memset(ssl_param, 0, sizeof(ssl_ctx_opt_t));
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
    // memset already made buff 0
    memcpy(state->context_password, state->password, state->password_length);

    if (EVP_MAX_MD_SIZE % sizeof(uint64_t) != 0)
    {
        LOGF("Assert Error: RealityClient-> EVP_MAX_MD_SIZE not a multiple of 8");
        return NULL;
    }

    uint64_t *p64 = (uint64_t *) state->hashes;
    p64[0]        = CALC_HASH_BYTES(state->password, strlen(state->password));
    for (int i = 1; i < EVP_MAX_MD_SIZE / sizeof(uint64_t); i++)
    {
        p64[i] = p64[i - 1];
    }

    ssl_param->verify_peer = state->verify ? 1 : 0;
    ssl_param->endpoint    = kSslClient;
    // ssl_param->ca_path = "cacert.pem";
    state->ssl_context = sslCtxNew(ssl_param);
    free(ssl_param);
    // SSL_CTX_load_verify_store(state->ssl_context,cacert_bytes);

    if (state->ssl_context == NULL)
    {
        LOGF("RealityClient: Could not create ssl context");
        return NULL;
    }

    size_t alpn_len = strlen(state->alpn);
    struct
    {
        uint8_t len;
        char    alpn_data[];
    } *ossl_alpn = malloc(1 + alpn_len);

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

api_result_t apiRealityClient(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyRealityClient(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataRealityClient()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
