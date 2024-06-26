#include "reality_server.h"
#include "basic_types.h"
#include "buffer_pool.h"
#include "buffer_stream.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "reality_helpers.h"
#include "shiftbuffer.h"
#include "tunnel.h"
#include "utils/jsonutils.h"
#include "utils/mathutils.h"
#include <openssl/evp.h>

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
    uint8_t      hashes[EVP_MAX_MD_SIZE];
    char         context_password[kSignPasswordLen];
    uint32_t     max_delta_time;
    uint32_t     counter_threshould;
    char        *password;
    unsigned int password_length;

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
        destroyBufferStream(cstate->read_stream);
        EVP_CIPHER_CTX_free(cstate->encryption_context);
        EVP_CIPHER_CTX_free(cstate->decryption_context);
        EVP_MD_CTX_free(cstate->sign_context);
        EVP_MD_free(cstate->msg_digest);
        EVP_PKEY_free(cstate->sign_key);

        free(cstate);
        CSTATE_DROP(c);
    }
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

            uint8_t tls_header[1 + 2 + 2];

            bufferStreamPush(cstate->read_stream, newShallowShiftBuffer(c->line->tid,buf));
            while (isAlive(c->line) && bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen)
            {
                bufferStreamViewBytesAt(cstate->read_stream, 0, tls_header, kTLSHeaderlen);
                uint16_t length = ntohs(*(uint16_t *) (tls_header + 3));

                if ((int) bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen + length)
                {
                    shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, kTLSHeaderlen + length);
                    shiftr(buf, kTLSHeaderlen);

                    if (verifyMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key))
                    {
                        reuseContextBuffer(c);
                        cstate->auth_state = kConAuthorized;

                        state->dest->upStream(state->dest, newFinContextFrom(c));
                        self->up->upStream(self->up, newInitContext(c->line));
                        if (! isAlive(c->line))
                        {
                            reuseBuffer(getContextBufferPool(c), buf);
                            destroyContext(c);

                            return;
                        }

                        buf = genericDecrypt(buf, cstate->decryption_context, state->context_password,
                                             getContextBufferPool(c));
                        cstate->first_sent = true;
                        context_t *plain_data_ctx = newContextFrom(c);
                        plain_data_ctx->payload   = buf;
                        plain_data_ctx->first = true;
                        self->up->upStream(self->up, plain_data_ctx);

                        if (! isAlive(c->line))
                        {
                            destroyContext(c);
                            return;
                        }
                        goto authorized;
                    }
                    else
                    {
                        reuseBuffer(getContextBufferPool(c), buf);
                    }
                }
                else
                {
                    break;
                }
            }

            cstate->giveup_counter -= 0;
            if (cstate->giveup_counter == 0)
            {
                empytBufferStream(cstate->read_stream);
                cstate->auth_state = kConUnAuthorized;
            }
        }
            // fallthrough

        case kConUnAuthorized:
            state->dest->upStream(state->dest, c);

            break;
        case kConAuthorized: {
            bufferStreamPushContextPayload(cstate->read_stream,c);
        authorized:;
            uint8_t tls_header[1 + 2 + 2];
            while (isAlive(c->line) && bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen)
            {
                bufferStreamViewBytesAt(cstate->read_stream, 0, tls_header, kTLSHeaderlen);
                uint16_t length = ntohs(*(uint16_t *) (tls_header + 3));
                if ((int) bufferStreamLen(cstate->read_stream) >= kTLSHeaderlen + length)
                {
                    shift_buffer_t *buf = bufferStreamRead(cstate->read_stream, kTLSHeaderlen + length);
                    bool            is_tls_applicationdata = ((uint8_t *) rawBuf(buf))[0] == kTLS12ApplicationData;
                    uint16_t        tls_ver_b;
                    memcpy(&tls_ver_b, ((uint8_t *) rawBuf(buf)) + 1, sizeof(uint16_t));
                    bool is_tls_33 = tls_ver_b == kTLSVersion12;
                    shiftr(buf, kTLSHeaderlen);

                    if (! verifyMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key) ||
                        ! is_tls_applicationdata || ! is_tls_33)
                    {
                        LOGE("RealityServer: verifyMessage failed");
                        reuseBuffer(getContextBufferPool(c), buf);
                        goto failed;
                    }

                    buf = genericDecrypt(buf, cstate->decryption_context, state->context_password,
                                         getContextBufferPool(c));

                    context_t *plain_data_ctx = newContextFrom(c);
                    plain_data_ctx->payload   = buf;

                    if (WW_UNLIKELY(! cstate->first_sent))
                    {
                        plain_data_ctx->first = true;
                        cstate->first_sent     = true;
                    }
                    self->up->upStream(self->up, plain_data_ctx);
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
            cstate = CSTATE_MUT(c) = malloc(sizeof(reality_server_con_state_t));
            memset(CSTATE(c), 0, sizeof(reality_server_con_state_t));
            cstate->auth_state         = kConAuthPending;
            cstate->giveup_counter     = state->counter_threshould;
            cstate->encryption_context = EVP_CIPHER_CTX_new();
            cstate->decryption_context = EVP_CIPHER_CTX_new();
            cstate->read_stream        = newBufferStream(getContextBufferPool(c));
            cstate->sign_context       = EVP_MD_CTX_create();
            cstate->msg_digest         = (EVP_MD *) EVP_get_digestbyname(MSG_DIGEST_ALG);
            int sk_size                = EVP_MD_size(cstate->msg_digest);
            cstate->sign_key           = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, state->hashes, sk_size);

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

        switch (cstate->auth_state)
        {
        case kConAuthPending:
        case kConUnAuthorized:
            self->dw->downStream(self->dw, c);
            break;
        case kConAuthorized:;
            shift_buffer_t *buf           = c->payload;
            c->payload                    = NULL;
            const unsigned int chunk_size = ((1 << 16) - (kSignLen + (2 * kEncryptionBlockSize) + kIVlen));

            if (bufLen(buf) < chunk_size)
            {
                buf = genericEncrypt(buf, cstate->encryption_context, state->context_password, getContextBufferPool(c));
                signMessage(buf, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
                appendTlsHeader(buf);
                assert(bufLen(buf) % 16 == 5);
                c->payload = buf;
                self->dw->downStream(self->dw, c);
            }
            else
            {
                while (bufLen(buf) > 0 && isAlive(c->line))
                {
                    const uint16_t  remain = (uint16_t) min(bufLen(buf), chunk_size);
                    shift_buffer_t *chunk  = shallowSliceBuffer(c->line->tid,buf, remain);
                    chunk                  = genericEncrypt(chunk, cstate->encryption_context, state->context_password,
                                                            getContextBufferPool(c));
                    signMessage(chunk, cstate->msg_digest, cstate->sign_context, cstate->sign_key);
                    appendTlsHeader(chunk);
                    context_t *cout = newContextFrom(c);
                    cout->payload   = chunk;
                    assert(bufLen(chunk) % 16 == 5);
                    self->dw->downStream(self->dw, cout);
                }
                reuseBuffer(getContextBufferPool(c), buf);
                destroyContext(c);
            }

            break;
        }
    }
    else
    {
        if (c->est)
        {
            if (cstate->auth_state == kConAuthorized)
            {
                destroyContext(c);
                return;
            }
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
        LOGF("JSON Error: RealityServer->settings->password (string field) : The data was empty or invalid");
        return NULL;
    }
    getIntFromJsonObjectOrDefault((int *) &(state->counter_threshould), settings, "sniffing-counter", 7);
    getIntFromJsonObjectOrDefault((int *) &(state->max_delta_time), settings, "max-delta-time", 10);

    state->password_length = (int) strlen(state->password);
    if (state->password_length < 3)
    {
        LOGF("JSON Error: RealityServer->settings->password (string field) : password is too short");
        return NULL;
    }
    // memset already made buff 0
    memcpy(state->context_password, state->password, state->password_length);
    if (EVP_MAX_MD_SIZE % sizeof(uint64_t) != 0)
    {
        LOGF("Assert Error: RealityServer-> EVP_MAX_MD_SIZE not a multiple of 8");
        return NULL;
    }
    uint64_t *p64 = (uint64_t *) state->hashes;
    p64[0]        = CALC_HASH_BYTES(state->password, strlen(state->password));
    for (int i = 1; i < (int) (EVP_MAX_MD_SIZE / sizeof(uint64_t)); i++)
    {
        p64[i] = p64[i - 1];
    }

    char *dest_node_name = NULL;
    if (! getStringFromJsonObject(&dest_node_name, settings, "destination"))
    {
        LOGW("RealityServer: no destination node provided in json");
        return NULL;
    }

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

    tunnel_t *t = newTunnel();
    chainDown(t, state->dest);
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

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

tunnel_metadata_t getMetadataRealityServer(void)
{
    return (tunnel_metadata_t){.version = 0001, .flags = 0x0};
}
