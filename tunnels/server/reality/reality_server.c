#include "reality_server.h"
#include "basic_types.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "frand.h"
#include "hloop.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "openssl_globals.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/jsonutils.h"
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

enum reality_consts
{
    kEncryptionBlockSize  = 16,
    kSignLen              = (224 / 8),
    kSignPasswordLen      = kEncryptionBlockSize,
    kIVlen                = 16, // iv size for *most* modes is the same as the block size. For AES this is 128 bits
    kTLSVersion12         = 0x0303,
    kTLS12ApplicationData = 0x17,
    kTLSHeaderlen         = 1 + 2 + 2,
};

enum connection_auth_state
{
    kConAuthPending,
    kConUnAuthorized,
    kConAuthorized
};

typedef struct reality_server_state_s
{

    tunnel_t *dest;
    // settings
    bool         anti_tit; // solve tls in tls using paddings
    uint32_t     max_delta_time;
    uint32_t     counter_threshould;
    char        *password;
    unsigned int password_length;
    uint8_t      hashes[EVP_MAX_MD_SIZE];
    char         context_password[kSignPasswordLen];

} reality_server_state_t;

typedef struct reality_server_con_state_s
{
    EVP_MD                    *msg_digest;
    EVP_PKEY                  *sign_key;
    EVP_MD_CTX                *sign_context;
    EVP_CIPHER_CTX            *encryption_context;
    EVP_CIPHER_CTX            *decryption_context;
    buffer_stream_t           *read_stream;
    uint8_t                    giveup_counter;
    enum connection_auth_state auth_state;
    bool                       first_sent;
    bool                       init_sent;
    uint32_t                   reply_sent_tit;

} reality_server_con_state_t;

// static size_t paddingDecisionCb(SSL *ssl, int type, size_t len, void *arg)
// {
//     (void) ssl;
//     (void) type;
//     (void) len;
//     reality_server_con_state_t *cstate = arg;

//     if (cstate->reply_sent_tit >= 1 && cstate->reply_sent_tit < 6)
//     {
//         return (16 * (160 + (0x7F & (size_t) fastRand())));
//     }

//     return 0;
// }

static void cleanup(tunnel_t *self, context_t *c)
{
    reality_server_con_state_t *cstate = CSTATE(c);
    if (cstate != NULL)
    {

        if (cstate->auth_state == kConAuthorized)
        {
            destroyBufferStream(cstate->read_stream);
        }
        EVP_CIPHER_CTX_free(cstate->encryption_context);
        EVP_CIPHER_CTX_free(cstate->decryption_context);
        EVP_MD_CTX_free(cstate->sign_context);
        EVP_MD_free(cstate->msg_digest);
        EVP_PKEY_free(cstate->sign_key);

        free(cstate);
        CSTATE_MUT(c) = NULL;
    }
}
static bool verifyMessage(shift_buffer_t *buf, reality_server_con_state_t *cstate)
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

static void signMessage(shift_buffer_t *buf, reality_server_con_state_t *cstate)
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

static shift_buffer_t *genericDecrypt(shift_buffer_t *in, reality_server_con_state_t *cstate, char *password,
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
static shift_buffer_t *genericEncrypt(shift_buffer_t *in, reality_server_con_state_t *cstate, char *password,
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
    reality_server_state_t     *state  = STATE(self);
    reality_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {

        switch (cstate->auth_state)
        {
        case kConAuthPending: {

            shift_buffer_t *buf = c->payload;
            shiftr(buf, kTLSHeaderlen);
            bool valid = verifyMessage(buf, cstate);
            shiftl(buf, kTLSHeaderlen);

            if (valid)
            {
                cstate->auth_state  = kConAuthorized;
                cstate->read_stream = newBufferStream(getContextBufferPool(c));

                state->dest->upStream(state->dest, newFinContextFrom(c));
                self->up->upStream(self->up, newInitContext(c->line));

                goto authorized;
            }
            else
            {
                cstate->giveup_counter -= 0;
                if (cstate->giveup_counter == 0)
                {
                    cstate->auth_state = kConUnAuthorized;
                }
            }
        }

        case kConUnAuthorized:
            state->dest->upStream(state->dest, c);

            break;
        authorized:;
        case kConAuthorized: {
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
                        LOGE("RealityServer: verifyMessage failed");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto failed;
                    }

                    buf             = genericDecrypt(buf, cstate, state->context_password, getContextBufferPool(c));
                    uint16_t length = 0;
                    readUI16(buf, &(length));
                    shiftr(buf, sizeof(uint16_t));
                    assert(length <= bufLen(buf));
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
        }

        break;
        }
    }
    else
    {

        if (c->init)
        {
            CSTATE_MUT(c) = malloc(sizeof(reality_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(reality_server_con_state_t));
            cstate->auth_state         = kConAuthPending;
            cstate->giveup_counter     = state->counter_threshould;
            cstate->encryption_context = EVP_CIPHER_CTX_new();
            cstate->decryption_context = EVP_CIPHER_CTX_new();

            state->dest->upStream(state->dest, c);
        }
        else if (c->fin)
        {

            tunnel_t *next = (cstate->auth_state == kConAuthorized) ? self->up : state->dest;
            cleanup(self, c);
            next->upStream(next, c);
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

static void downStream(tunnel_t *self, context_t *c)
{
    reality_server_state_t     *state  = STATE(self);
    reality_server_con_state_t *cstate = CSTATE(c);

    if (c->payload != NULL)
    {
        if (state->anti_tit && isAuthenticated(c->line))
        {
            cstate->reply_sent_tit += 1;
        }

        switch (cstate->auth_state)
        {
        case kConAuthPending:
        case kConUnAuthorized:

            if (cstate->send_counter != 2)
            {
                cstate->send_counter += 1;
                if (cstate->send_counter == 2)
                {
                    LOGD("RealityServer: second reply was %d bytes", (int) bufLen(c->payload));
                    cstate->magic = CALC_HASH_BYTES(rawBuf(c->payload), bufLen(c->payload));
                    LOGD("RealityServer: magic = %02x", cstate->magic);
                }
            }
            self->dw->downStream(self->dw, c);

            break;
        case kConAuthorized:

            break;
        }

        reuseContextBuffer(c);
        destroyContext(c);
    }
    else
    {
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
    }
}

tunnel_t *newRealityServer(node_instance_context_t *instance_info)
{
    reality_server_state_t *state = malloc(sizeof(reality_server_state_t));
    memset(state, 0, sizeof(reality_server_state_t));
    const cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: RealityServer->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->password), settings, "password"))
    {
        LOGF("JSON Error: RealityClient->settings->password (string field) : The data was empty or invalid");
        return NULL;
    }
    getIntFromJsonObjectOrDefault((int *) &(state->counter_threshould), settings, "sniffing-counter", 5);
    getIntFromJsonObjectOrDefault((int *) &(state->max_delta_time), settings, "max-delta-time", 10);

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
        const uint8_t seed        = (uint8_t) (state->hash3 * (i + 7));
        state->context_base_iv[i] = (uint8_t) (CALC_HASH_PRIMITIVE(seed));
    }

    char *dest_node_name = NULL;
    if (! getStringFromJsonObject(&dest_node_name, settings, "destination"))
    {
        LOGW("RealityServer: no destination node provided in json");
        return NULL;
    }
    LOGD("RealityServer: accessing destination node");

    hash_t  hash_next = CALC_HASH_BYTES(dest_node_name, strlen(dest_node_name));
    node_t *next_node = getNode(hash_next);
    if (next_node == NULL)
    {
        LOGF("RealityServer: destination node not found");
        exit(1);
    }

    if (next_node->instance == NULL)
    {
        runNode(next_node, instance_info->chain_index + 1);
    }

    state->dest = next_node->instance;
    free(dest_node_name);
    getBoolFromJsonObjectOrDefault(&(state->anti_tit), settings, "anti-tls-in-tls", false);

    tunnel_t *t = newTunnel();
    chainDown(t, state->dest);
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;
    atomic_thread_fence(memory_order_release);
    return t;
}

api_result_t apiRealityServer(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t){0};
}

tunnel_t *destroyRealityServer(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataRealityServer()
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
