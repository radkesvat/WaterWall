#include "structure.h"

#include "loggers/network_logger.h"

#include <openssl/base64.h>
#include <openssl/crypto.h>

typedef struct tlsclient_ech_config_s
{
    size_t  length;
    uint8_t bytes[];
} tlsclient_ech_config_t;

static int     tlsclientEchContextIndex = -1;
static wonce_t tlsclientEchIndexOnce    = WONCE_INIT;

static void tlsclientEchConfigFree(void *parent, void *ptr, CRYPTO_EX_DATA *data, int index, long argl, void *argp)
{
    discard parent;
    discard data;
    discard index;
    discard argl;
    discard argp;
    OPENSSL_free(ptr);
}

static void tlsclientEchIndexInit(void)
{
    tlsclientEchContextIndex = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, tlsclientEchConfigFree);
}

bool tlsclientConfigureEchContexts(tlsclient_tstate_t *ts, const cJSON *settings)
{
    assert(ts != NULL && settings != NULL && ts->threadlocal_ssl_contexts != NULL);
    const cJSON *configured = NULL;
    const cJSON *item;
    cJSON_ArrayForEach(item, settings)
    {
        if (stringCompare(item->string, "ech-config-list") != 0)
            continue;
        if (configured != NULL || ! cJSON_IsString(item) || item->valuestring == NULL)
        {
            LOGF("TlsClient: 'ech-config-list' must be a single non-empty base64 string");
            return false;
        }
        configured = item;
    }
    if (configured == NULL)
        return true;
    if (ts->ech_grease_sni_override != NULL)
    {
        LOGF("TlsClient: 'ech-config-list' cannot be combined with 'ech-sni-trick'");
        return false;
    }

    /* ECHConfigList is a uint16-length-prefixed vector, including its two-byte prefix. */
    const size_t maximum_bytes  = UINT16_MAX + 2U;
    const size_t encoded_length = stringLength(configured->valuestring);
    size_t       capacity;
    if (encoded_length == 0 || encoded_length > ((maximum_bytes + 2U) / 3U) * 4U ||
        ! EVP_DecodedLength(&capacity, encoded_length))
    {
        LOGF("TlsClient: 'ech-config-list' is not a bounded base64 ECHConfigList");
        return false;
    }

    uint8_t *decoded        = OPENSSL_malloc(capacity);
    size_t   decoded_length = 0;
    if (decoded == NULL)
        return false;
    if (! EVP_DecodeBase64(
            decoded, &decoded_length, capacity, (const uint8_t *) configured->valuestring, encoded_length) ||
        decoded_length < 2 || decoded_length > maximum_bytes)
    {
        LOGF("TlsClient: 'ech-config-list' is not a valid base64 ECHConfigList");
        OPENSSL_free(decoded);
        return false;
    }

    wonce(&tlsclientEchIndexOnce, tlsclientEchIndexInit);
    bool success = tlsclientEchContextIndex >= 0;
    for (wid_t i = 0; success && i < getWorkersCount(); ++i)
    {
        SSL_CTX *context = ts->threadlocal_ssl_contexts[i];
        assert(SSL_CTX_get_ex_data(context, tlsclientEchContextIndex) == NULL);
        tlsclient_ech_config_t *config = OPENSSL_malloc(sizeof(*config) + decoded_length);
        if (config == NULL)
        {
            success = false;
            break;
        }
        config->length = decoded_length;
        memoryCopy(config->bytes, decoded, decoded_length);
        if (! SSL_CTX_set_ex_data(context, tlsclientEchContextIndex, config))
        {
            OPENSSL_free(config);
            success = false;
        }
    }
    OPENSSL_free(decoded);
    return success;
}

bool tlsclientConfigureEchForSsl(SSL *ssl)
{
    assert(ssl != NULL && ! SSL_is_init_finished(ssl));
    wonce(&tlsclientEchIndexOnce, tlsclientEchIndexInit);
    if (tlsclientEchContextIndex < 0)
        return true; /* No successfully constructed node can have configured ECH. */
    const tlsclient_ech_config_t *config = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), tlsclientEchContextIndex);
    if (config == NULL)
        return true;

    /* A supplied configuration requires real ECH. Unsupported configurations
     * must not silently turn the private SNI into a GREASE-only ClientHello. */
    SSL_set_reject_unusable_ech_config(ssl, 1);
    return SSL_set1_ech_config_list(ssl, config->bytes, config->length) == 1;
}
