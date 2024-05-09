#include "reality_client.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "context_queue.h"
#include "frand.h"
#include "loggers/network_logger.h"
#include "openssl_globals.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/hashutils.h"
#include "utils/jsonutils.h"
#include "utils/mathutils.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <string.h>

// these should not be modified, code may break
enum reality_consts
{
    kEncryptionBlockSize  = 16,
    kSignLen              = (224 / 8),
    kSignPasswordLen      = kEncryptionBlockSize,
    kIVlen                = 16, // iv size for *most* modes is the same as the block size. For AES this is 128 bits
    kTLSVersion12         = 0x0303,
    kTLS12ApplicationData = 0x17,
};

typedef struct reailty_client_state_s
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

} reailty_client_state_t;

typedef struct reailty_client_con_state_s
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

static bool verifyMessage(shift_buffer_t *buf, reailty_client_con_state_t *cstate)
{
    int     rc = EVP_DigestSignInit(cstate->sign_context, NULL, cstate->msg_digest, NULL, cstate->sign_key);
    uint8_t expect[EVP_MAX_MD_SIZE];
    memcpy(expect, rawBuf(buf), kSignLen);
    shiftr(buf, kSignLen);
    assert(rc == 1);
    rc = EVP_DigestSignUpdate(cstate->sign_context, rawBuf(buf), bufLen(buf));
    assert(rc == 1);
    uint8_t buff[EVP_MAX_MD_SIZE];
    size_t  size = sizeof(buff);
    rc           = EVP_DigestSignFinal(cstate->sign_context, buff, &size);
    assert(rc == 1);
    assert(size == kSignLen);
    return ! ! CRYPTO_memcmp(expect, buff, size);
}

static void signMessage(shift_buffer_t *buf, reailty_client_con_state_t *cstate)
{
    int rc = EVP_DigestSignInit(cstate->sign_context, NULL, cstate->msg_digest, NULL, cstate->sign_key);
    assert(rc == 1);
    rc = EVP_DigestSignUpdate(cstate->sign_context, rawBuf(buf), bufLen(buf));
    assert(rc == 1);
    size_t req = 0;
    rc         = EVP_DigestSignFinal(cstate->sign_context, NULL, &req);
    assert(rc == 1);
    shiftl(buf, req);
    size_t slen = 0;
    rc          = EVP_DigestSignFinal(cstate->sign_context, rawBufMut(buf), &slen);
    assert(rc == 1);
    assert(req == slen == kSignLen);
}

static shift_buffer_t *genericDecrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, char *password,
                                      buffer_pool_t *pool)
{
    shift_buffer_t *out          = popBuffer(pool);
    uint16_t        input_length = bufLen(in);

    uint8_t iv[kIVlen];
    memcpy(iv, rawBuf(in), kIVlen);
    shiftr(in, kIVlen);

    EVP_DecryptInit_ex(cstate->decryption_context, EVP_aes_128_cbc(), NULL, (const uint8_t *) password,
                       (const uint8_t *) iv);

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
    reuseBuffer(pool, in);

    setLen(out, bufLen(out) + out_len);
    return out;
}
static shift_buffer_t *genericEncrypt(shift_buffer_t *in, reailty_client_con_state_t *cstate, char *password,
                                      buffer_pool_t *pool)
{
    shift_buffer_t *out          = popBuffer(pool);
    int             input_length = (int) bufLen(in);

    uint8_t iv[kIVlen];
    for (int i; i < kIVlen / sizeof(uint32_t); i++)
    {
        ((uint32_t *) iv)[i] = fastRand();
    }

    EVP_EncryptInit_ex(cstate->encryption_context, EVP_aes_128_cbc(), NULL, (const uint8_t *) password,
                       (const uint8_t *) iv);

    reserveBufSpace(out, input_length + (input_length % kEncryptionBlockSize));
    int out_len = 0;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(cstate->encryption_context, rawBufMut(out), &out_len, rawBuf(in), input_length))
    {
        printSSLErrorAndAbort();
    }

    setLen(out, bufLen(out) + out_len);

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(cstate->encryption_context, rawBufMut(out) + out_len, &out_len))
    {
        printSSLErrorAndAbort();
    }
    reuseBuffer(pool, in);
    setLen(out, bufLen(out) + out_len);

    shiftl(out, kIVlen);
    memcpy(rawBufMut(out), iv, kIVlen);
    return out;
}

static void appendTlsHeader(shift_buffer_t *buf)
{
    unsigned int data_length = bufLen(buf);
    assert(data_length < (1U << 16));

    shiftl(buf, sizeof(uint16_t));
    writeUI16(buf, (uint16_t) data_length);

    shiftl(buf, sizeof(uint16_t));
    writeUI16(buf, kTLSVersion12);

    shiftl(buf, sizeof(uint8_t));
    writeUI8(buf, kTLS12ApplicationData);
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
        // todo (research) about encapsulation order and safety, CMAC HMAC
        shift_buffer_t *buf = c->payload;
        while (bufLen(buf) > 0)
        {
            const int       chunk_size = ((1 << 16) - (1 + kSignLen + kEncryptionBlockSize + kIVlen));
            const uint16_t  remain     = (uint16_t) min(bufLen(buf), chunk_size);
            shift_buffer_t *chunk      = shallowSliceBuffer(buf, remain);
            shiftl(chunk, 2);
            writeUI16(chunk, remain);
            chunk = genericEncrypt(chunk, cstate, state->context_password, getContextBufferPool(c));
            signMessage(chunk, cstate);
            appendTlsHeader(chunk);
            context_t *cout = newContextFrom(c);
            cout->payload   = chunk;
            assert(bufLen(chunk) % 16 == 5);
            self->up->upStream(self->up, cout);
        }
        reuseContextBuffer(c);
        destroyContext(c);
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
            cstate->sign_context               = EVP_MD_CTX_create();
            cstate->encryption_context         = EVP_CIPHER_CTX_new();
            cstate->decryption_context         = EVP_CIPHER_CTX_new();
            cstate->msg_digest                 = (EVP_MD *) EVP_get_digestbyname("SHA256");
            int sk_size                        = EVP_MD_size(cstate->msg_digest);
            cstate->sign_key                   = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, state->hashes, sk_size);

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
    reailty_client_state_t     *state  = STATE(self);
    reailty_client_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        if (cstate->handshake_completed)
        {
            bufferStreamPush(cstate->read_stream, c->payload);
            c->payload = NULL;
            uint8_t tls_header[1 + 2 + 2];
            while (bufferStreamLen(cstate->read_stream) >= sizeof(tls_header))
            {
                bufferStreamViewBytesAt(cstate->read_stream, 0, tls_header, sizeof(tls_header));
                uint16_t length = *(uint16_t *) (tls_header + 3);
                if (bufferStreamLen(cstate->read_stream) >= sizeof(tls_header) + length)
                {
                    shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, sizeof(tls_header) + length);
                    shiftr(buf, sizeof(tls_header));

                    if (! verifyMessage(buf, cstate))
                    {
                        LOGE("RealityClient: verifyMessage failed");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto failed;
                    }

                    buf             = genericDecrypt(buf, cstate, state->context_password, getContextBufferPool(c));
                    uint16_t length = 0;
                    readUI16(buf, &(length));
                    shiftr(buf, sizeof(uint16_t));
                    setLen(buf, length);

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
                    LOGD("OpensslClient: Tls handshake complete");
                    reailty_client_state_t *state = STATE(self);

                    cstate->handshake_completed = true;
                    cstate->read_stream         = newBufferStream(getContextBufferPool(c));

                    context_t *dw_est_ctx = newContextFrom(c);
                    dw_est_ctx->est       = true;
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

    assert(EVP_MAX_MD_SIZE % sizeof(uint64_t) == 0);
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
