#include "reality_client.h"
#include "buffer_pool.h"
#include "frand.h"
#include "loggers/network_logger.h"
#include "openssl_globals.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/hashutils.h"
#include "utils/jsonutils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

// these should not be modified, code may break
enum reality_consts
{
    kEncryptionBlockSize  = 16,
    kSignHeaderLen        = kEncryptionBlockSize * 2,
    kSignPasswordLen      = kEncryptionBlockSize,
    kSignIVlen            = 16, // IV size for *most* modes is the same as the block size. For AES this is 128 bits
    kTLSVersion12         = 0x0303,
    kTLS12ApplicationData = 0x17,
};

typedef struct reailty_client_state_s
{

    ssl_ctx_t ssl_context;
    // settings
    char         *alpn;
    char         *sni;
    char         *password;
    int           password_length;
    bool          verify;
    uint64_t      hash1;
    uint64_t      hash2;
    uint64_t      hash3;
    char          context_password[kSignPasswordLen];
    unsigned char context_iv[kSignIVlen];

} reailty_client_state_t;

typedef struct reailty_client_con_state_s
{
    SSL             *ssl;
    BIO             *rbio;
    BIO             *wbio;
    EVP_CIPHER_CTX  *encryption_context;
    EVP_CIPHER_CTX  *decryption_context;
    context_queue_t *queue;
    bool             handshake_completed;
    bool             first_sent;
    uint32_t         epochsecs;

} reailty_client_con_state_t;

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
    reailty_client_con_state_t *cstate = CSTATE(c);
    if (cstate != NULL)
    {
        EVP_CIPHER_CTX_free(cstate->encryption_context);
        EVP_CIPHER_CTX_free(cstate->decryption_context);

        SSL_free(cstate->ssl); /* free the SSL object and its BIO's */
        destroyContextQueue(cstate->queue);

        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
}

static void flushWriteQueue(tunnel_t *self, context_t *c)
{
    reailty_client_con_state_t *cstate = CSTATE(c);

    while (contextQueueLen(cstate->queue) > 0)
    {
        self->upStream(self, contextQueuePop(cstate->queue));

        if (! isAlive(c->line))
        {
            return;
        }
    }
}
static void genericDecrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, shift_buffer_t *out)
{
    uint16_t input_length = bufLen(in);
    reserveBufSpace(out, input_length + (2 * kEncryptionBlockSize));
    int out_len = 0;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(cstate->decryption_context, rawBufMut(out), &out_len, rawBuf(in), input_length))
    {
        printSSLErrorAndAbort();
    }
    setLen(out, out_len);

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(cstate->decryption_context, rawBufMut(out) + out_len, &out_len))
    {
        printSSLErrorAndAbort();
    }
    setLen(out, bufLen(out) + out_len);
}
static void genericEncrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, shift_buffer_t *out)
{
    uint16_t input_length = bufLen(in);
    reserveBufSpace(out, input_length + (2 * kEncryptionBlockSize));
    int out_len = 0;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(cstate->encryption_context, rawBufMut(out), &out_len, rawBuf(in), input_length))
    {
        printSSLErrorAndAbort();
    }

    setLen(out, out_len);

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(cstate->encryption_context, rawBufMut(out) + out_len, &out_len))
    {
        printSSLErrorAndAbort();
    }

    setLen(out, bufLen(out) + out_len);
}
static void otherPacketsEncrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, shift_buffer_t *out)
{

    genericEncrypt(in, cstate, out);

    unsigned int data_length = bufLen(out);
    assert(data_length % kEncryptionBlockSize == 0);

    shiftl(out, sizeof(uint16_t));
    writeUI16(out, data_length);

    shiftl(out, sizeof(uint16_t));
    writeUI16(out, kTLSVersion12);

    shiftl(out, sizeof(uint8_t));
    writeUI8(out, kTLS12ApplicationData);
}
static void firstPacketEncrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, uint64_t hash1, uint64_t hash2,
                               shift_buffer_t *out)
{

    genericEncrypt(in, cstate, out);

    shiftl(out, kSignHeaderLen);
    for (int i = 0; i < kSignHeaderLen / sizeof(uint32_t); i++)
    {
        ((uint32_t *) rawBufMut(out))[i] = fastRand();
    }

    const uint32_t max_start_pos = 1 + kSignHeaderLen - sizeof(uint32_t);
    uint32_t       start_pos     = ((uint32_t) hash1) % max_start_pos;

    uint32_t *u32_p = (uint32_t *) (((char *) rawBufMut(out)) + start_pos);
    *u32_p          = cstate->epochsecs;

    for (int i = 0; i < kSignHeaderLen / sizeof(uint64_t); i++)
    {
        ((uint64_t *) rawBufMut(out))[i] = ((uint64_t *) rawBufMut(out))[i] ^ hash2;
    }

    unsigned int data_length = bufLen(out);
    assert(data_length % kEncryptionBlockSize == 0);

    shiftl(out, sizeof(uint16_t));
    writeUI16(out, data_length);

    shiftl(out, sizeof(uint16_t));
    writeUI16(out, kTLSVersion12);

    shiftl(out, sizeof(uint8_t));
    writeUI8(out, kTLS12ApplicationData);
}

static void upStream(tunnel_t *self, context_t *c)
{
    reailty_client_state_t *state = STATE(self);

    if (c->payload != NULL)
    {
        reailty_client_con_state_t *cstate = CSTATE(c);

        if (! cstate->handshake_completed)
        {
            contextQueuePush(cstate->queue, c);
            return;
        }
        shift_buffer_t *cypher_buf = popBuffer(getContextBufferPool(c));

        if (WW_LIKELY(cstate->first_sent))
        {
            otherPacketsEncrypt(c->payload, cstate, cypher_buf);
        }
        else
        {
            firstPacketEncrypt(c->payload, cstate, state->hash1, state->hash2, cypher_buf);
        }
        reuseContextBuffer(c);
        c->payload = cypher_buf;

        self->up->upStream(self->up, c);
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(reailty_client_con_state_t));
            memset(CSTATE(c), 0, sizeof(reailty_client_con_state_t));
            reailty_client_con_state_t *cstate = CSTATE(c);
            cstate->rbio                       = BIO_new(BIO_s_mem());
            cstate->wbio                       = BIO_new(BIO_s_mem());
            cstate->ssl                        = SSL_new(state->ssl_context);
            cstate->queue                      = newContextQueue(getContextBufferPool(c));
            cstate->encryption_context         = EVP_CIPHER_CTX_new();
            cstate->decryption_context         = EVP_CIPHER_CTX_new();
            cstate->epochsecs                  = (uint32_t) time(NULL);
            unsigned char iv[kSignIVlen];

            for (int i = 0; i < kSignIVlen; i++)
            {
                iv[i] = (uint8_t) (state->context_iv[i] + cstate->epochsecs);
            }

            EVP_EncryptInit_ex(cstate->encryption_context, EVP_aes_128_cbc(), NULL,
                               (const uint8_t *) state->context_password, (const uint8_t *) iv);

            EVP_EncryptInit_ex(cstate->decryption_context, EVP_aes_128_cbc(), NULL,
                               (const uint8_t *) state->context_password, (const uint8_t *) iv);

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
    context_t *fail_context_up = newFinContextFrom(c);
    fail_context_up->src_io    = c->src_io;
    self->up->upStream(self->up, fail_context_up);

    context_t *fail_context = newFinContextFrom(c);
    cleanup(self, c);
    destroyContext(c);
    self->dw->downStream(self->dw, fail_context);
}

static void downStream(tunnel_t *self, context_t *c)
{
    reailty_client_con_state_t *cstate = CSTATE(c);

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

                if (SSL_is_init_finished(cstate->ssl))
                {
                    LOGD("OpensslClient: Tls handshake complete");
                    cstate->handshake_completed = true;
                    context_t *dw_est_ctx       = newContextFrom(c);
                    dw_est_ctx->est             = true;
                    self->dw->downStream(self->dw, dw_est_ctx);
                    if (! isAlive(c->line))
                    {
                        LOGW("OpensslClient: prev node instantly closed the est with fin");
                        reuseContextBuffer(c);
                        destroyContext(c);
                        return;
                    }
                    flushWriteQueue(self, c);
                    // queue is flushed and we are done
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

tunnel_t *newRealityClient(node_instance_context_t *instance_info)
{
    reailty_client_state_t *state = malloc(sizeof(reailty_client_state_t));
    memset(state, 0, sizeof(reailty_client_state_t));

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
    }
    // memset already made buff 0
    memcpy(state->context_password, state->password, state->password_length);

    state->hash1 = CALC_HASH_BYTES(state->password, strlen(state->password));
    state->hash2 = CALC_HASH_PRIMITIVE(state->hash1);
    state->hash3 = CALC_HASH_PRIMITIVE(state->hash2);
    // the iv must be unpredictable, so initializing it from password
    for (int i = 0; i < kSignIVlen; i++)
    {
        const uint8_t seed   = (uint8_t) (state->hash3 * (i + 7));
        state->context_iv[i] = (uint8_t) (CALC_HASH_PRIMITIVE(seed));
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
