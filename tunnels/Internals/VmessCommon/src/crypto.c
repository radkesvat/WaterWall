#include "VmessCommon/crypto.h"

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x30300000L
#error "VMess requires OpenSSL 3.3 or newer for streaming SHAKE128"
#endif

/* Wire behavior follows V2Fly v5.53.0 proxy/vmess/{aead,encoding}.
 * Only the protocol's nested HMAC construction is implemented here; all digest,
 * block-cipher, AEAD and XOF primitives are provided by OpenSSL. */

static uint16_t read16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint32_t read32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
}

static void write16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8);
    p[1] = (uint8_t) value;
}

static void write32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t) (value >> 24);
    p[1] = (uint8_t) (value >> 16);
    p[2] = (uint8_t) (value >> 8);
    p[3] = (uint8_t) value;
}

static uint32_t crc32Ieee(const uint8_t *p, size_t length)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < length; ++i)
    {
        crc ^= p[i];
        for (unsigned bit = 0; bit < 8; ++bit)
        {
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

static uint32_t fnv1a32(const uint8_t *p, size_t length)
{
    uint32_t hash = UINT32_C(2166136261);
    for (size_t i = 0; i < length; ++i)
    {
        hash = (hash ^ p[i]) * UINT32_C(16777619);
    }
    return hash;
}

static bool digest(const EVP_MD *algorithm, const uint8_t *input, size_t length, uint8_t *out, unsigned expected)
{
    unsigned actual = 0;
    return EVP_Digest(input, length, out, &actual, algorithm, NULL) == 1 && actual == expected;
}

/* H_n(m) = H_(n-1)(opad_n || H_(n-1)(ipad_n || m)). The base
 * H_0 is SHA256. One reusable digest context suffices because leaf calls are
 * synchronous, and bounded spans avoid secret-dependent temporary allocation. */
static bool kdfHash(EVP_MD_CTX *ctx, const vmess_kdf_segment_t *keys, size_t depth, const vmess_kdf_segment_t *message,
                    size_t count, uint8_t out[32])
{
    if (depth == 0)
    {
        unsigned actual = 0;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        {
            return false;
        }
        for (size_t i = 0; i < count; ++i)
        {
            if (EVP_DigestUpdate(ctx, message[i].data, message[i].length) != 1)
            {
                return false;
            }
        }
        return EVP_DigestFinal_ex(ctx, out, &actual) == 1 && actual == 32;
    }
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    uint8_t inner[32] = {0};
    memset(inner_pad, 0x36, sizeof(inner_pad));
    memset(outer_pad, 0x5c, sizeof(outer_pad));
    const vmess_kdf_segment_t *key = &keys[depth - 1];
    for (size_t i = 0; i < key->length; ++i)
    {
        inner_pad[i] ^= key->data[i];
        outer_pad[i] ^= key->data[i];
    }
    assert(count <= 5);
    vmess_kdf_segment_t spans[6];
    spans[0] = (vmess_kdf_segment_t) {inner_pad, sizeof(inner_pad)};
    memcpy(spans + 1, message, count * sizeof(*message));
    bool ok = kdfHash(ctx, keys, depth - 1, spans, count + 1, inner);
    if (ok)
    {
        spans[0] = (vmess_kdf_segment_t) {outer_pad, sizeof(outer_pad)};
        spans[1] = (vmess_kdf_segment_t) {inner, sizeof(inner)};
        ok       = kdfHash(ctx, keys, depth - 1, spans, 2, out);
    }
    wCryptoZero(inner, sizeof(inner));
    wCryptoZero(inner_pad, sizeof(inner_pad));
    wCryptoZero(outer_pad, sizeof(outer_pad));
    return ok;
}

wcrypto_status_t vmessKdf(const uint8_t *key, size_t key_length, const vmess_kdf_segment_t *path, size_t path_count,
                          uint8_t out[32])
{
    assert(out != NULL && (key != NULL || key_length == 0) && (path != NULL || path_count == 0));
    assert(path_count <= 3);
    static const uint8_t root[]  = "VMess AEAD KDF";
    vmess_kdf_segment_t  keys[4] = {{root, sizeof(root) - 1}};
    for (size_t i = 0; i < path_count; ++i)
    {
        assert(path[i].length <= 64 && (path[i].data != NULL || path[i].length == 0));
        keys[i + 1] = path[i];
    }
    const vmess_kdf_segment_t message = {key, key_length};
    EVP_MD_CTX               *ctx     = EVP_MD_CTX_new();
    bool                      ok      = ctx != NULL && kdfHash(ctx, keys, path_count + 1, &message, 1, out);
    EVP_MD_CTX_free(ctx);
    if (! ok)
    {
        wCryptoZero(out, 32);
    }
    return ok ? kWCryptoOk : kWCryptoBackendFailed;
}

static wcrypto_status_t kdfLabel(const uint8_t key[16], const char *label, uint8_t out[32])
{
    const vmess_kdf_segment_t path = {(const uint8_t *) label, strlen(label)};
    return vmessKdf(key, 16, &path, 1, out);
}

wcrypto_status_t vmessPrepareKey(const uint8_t uuid[16], vmess_prepared_key_t *out)
{
    assert(uuid != NULL && out != NULL);
    static const uint8_t salt[] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
    uint8_t              input[16 + sizeof(salt) - 1];
    uint8_t              derived[32] = {0};
    memcpy(input, uuid, 16);
    memcpy(input + 16, salt, sizeof(salt) - 1);
    wcrypto_status_t status = kWCryptoBackendFailed;
    if (digest(EVP_md5(), input, sizeof(input), out->cmd_key, 16))
    {
        status = kdfLabel(out->cmd_key, "AES Auth ID Encryption", derived);
        if (status == kWCryptoOk)
        {
            memcpy(out->auth_key, derived, 16);
        }
    }
    wCryptoZero(input, sizeof(input));
    wCryptoZero(derived, sizeof(derived));
    if (status != kWCryptoOk)
    {
        wCryptoZero(out, sizeof(*out));
    }
    return status;
}

wcrypto_status_t vmessAuthIdInit(vmess_auth_id_ctx_t *ctx)
{
    assert(ctx != NULL && ctx->cipher == NULL);
    ctx->cipher = EVP_CIPHER_CTX_new();
    if (ctx->cipher == NULL || EVP_DecryptInit_ex(ctx->cipher, EVP_aes_128_ecb(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx->cipher, 0) != 1)
    {
        vmessAuthIdDestroy(ctx);
        return kWCryptoBackendFailed;
    }
    return kWCryptoOk;
}

wcrypto_status_t vmessAuthIdCreate(const vmess_prepared_key_t *key, uint64_t timestamp, const uint8_t random[4],
                                   uint8_t out[16])
{
    assert(key && random && out);
    if ((timestamp >> 63) != 0)
    {
        return kWCryptoInvalidArgument;
    }
    uint8_t plain[16] = {0};
    write32(plain, (uint32_t) (timestamp >> 32));
    write32(plain + 4, (uint32_t) timestamp);
    memcpy(plain + 8, random, 4);
    write32(plain + 12, crc32Ieee(plain, 12));
    EVP_CIPHER_CTX *ctx          = EVP_CIPHER_CTX_new();
    int             written      = 0;
    int             final_length = 0;
    bool            ok = ctx != NULL && EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key->auth_key, NULL) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, out, &written, plain, sizeof(plain)) == 1 && written == 16 &&
              EVP_EncryptFinal_ex(ctx, out + written, &final_length) == 1 && final_length == 0;
    EVP_CIPHER_CTX_free(ctx);
    wCryptoZero(plain, sizeof(plain));
    if (! ok)
    {
        wCryptoZero(out, 16);
    }
    return ok ? kWCryptoOk : kWCryptoBackendFailed;
}

void vmessAuthIdDestroy(vmess_auth_id_ctx_t *ctx)
{
    assert(ctx != NULL);
    EVP_CIPHER_CTX_free(ctx->cipher);
    wCryptoZero(ctx, sizeof(*ctx));
}

wcrypto_status_t vmessAuthIdCheck(vmess_auth_id_ctx_t *ctx, const vmess_prepared_key_t *key, const uint8_t auth_id[16],
                                  uint64_t now, uint64_t *timestamp)
{
    assert(ctx != NULL && ctx->cipher != NULL && key != NULL && auth_id != NULL && timestamp != NULL);
    uint8_t          decoded[32]  = {0};
    int              length       = 0;
    int              final_length = 0;
    wcrypto_status_t status       = kWCryptoBackendFailed;
    if (EVP_DecryptInit_ex(ctx->cipher, NULL, NULL, key->auth_key, NULL) != 1 ||
        EVP_DecryptUpdate(ctx->cipher, decoded, &length, auth_id, 16) != 1 ||
        EVP_DecryptFinal_ex(ctx->cipher, decoded + length, &final_length) != 1 || length + final_length != 16)
    {
        goto done;
    }
    status = kWCryptoAuthenticationFailed;
    if (read32(decoded + 12) != crc32Ieee(decoded, 12))
    {
        goto done;
    }
    *timestamp = ((uint64_t) read32(decoded) << 32) | read32(decoded + 4);
    status     = kWCryptoRejectedKey;
    if ((*timestamp >> 63) == 0 && ((*timestamp >= now ? *timestamp - now : now - *timestamp) <= 120))
    {
        status = kWCryptoOk;
    }
done:
    wCryptoZero(decoded, sizeof(decoded));
    return status;
}

static wcrypto_status_t aead(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *algorithm, bool encrypt, const uint8_t *key,
                             const uint8_t nonce[12], const uint8_t *ad, size_t ad_length, const uint8_t *input,
                             size_t input_length, uint8_t *out, size_t capacity)
{
    if ((! encrypt && input_length < 16) || input_length > INT_MAX || ad_length > INT_MAX)
    {
        return kWCryptoInvalidArgument;
    }
    size_t data_length   = encrypt ? input_length : input_length - 16;
    size_t result_length = encrypt ? input_length + 16 : data_length;
    if (capacity < result_length)
    {
        return kWCryptoInputTooLarge;
    }
    uint8_t           empty[16]    = {0};
    uint8_t          *dest         = out != NULL ? out : empty;
    int               written      = 0;
    int               final_length = 0;
    wcrypto_status_t  status       = kWCryptoBackendFailed;
    const EVP_CIPHER *selected     = EVP_CIPHER_CTX_get0_cipher(ctx) == NULL ? algorithm : NULL;
    if (EVP_CipherInit_ex(ctx, selected, NULL, key, nonce, encrypt ? 1 : 0) != 1 ||
        (ad_length != 0 && EVP_CipherUpdate(ctx, NULL, &written, ad, (int) ad_length) != 1) ||
        EVP_CipherUpdate(ctx, dest, &written, input != NULL ? input : empty, (int) data_length) != 1 ||
        (size_t) written != data_length)
    {
        goto done;
    }
    if (! encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *) (input + data_length)) != 1)
    {
        goto done;
    }
    if (EVP_CipherFinal_ex(ctx, dest + written, &final_length) != 1)
    {
        status = encrypt ? kWCryptoBackendFailed : kWCryptoAuthenticationFailed;
        goto done;
    }
    if (final_length != 0 || (encrypt && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, dest + written) != 1))
    {
        goto done;
    }
    status = kWCryptoOk;
done:
    if (status != kWCryptoOk && out != NULL)
    {
        wCryptoZero(out, result_length);
    }
    wCryptoZero(empty, sizeof(empty));
    return status;
}

static wcrypto_status_t headerAead(const uint8_t key[16], const uint8_t iv[12], bool encrypt, const uint8_t *ad,
                                   size_t ad_length, const uint8_t *in, size_t length, uint8_t *out, size_t capacity)
{
    EVP_CIPHER_CTX  *ctx = EVP_CIPHER_CTX_new();
    wcrypto_status_t status =
        ctx == NULL ? kWCryptoBackendFailed
                    : aead(ctx, EVP_aes_128_gcm(), encrypt, key, iv, ad, ad_length, in, length, out, capacity);
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static wcrypto_status_t requestDerived(const uint8_t cmd_key[16], const uint8_t auth_id[16], const uint8_t nonce[8],
                                       const char *label, uint8_t out[32])
{
    const vmess_kdf_segment_t path[] = {{(const uint8_t *) label, strlen(label)}, {auth_id, 16}, {nonce, 8}};
    return vmessKdf(cmd_key, 16, path, 3, out);
}

static wcrypto_status_t requestCrypt(const uint8_t cmd_key[16], const uint8_t auth_id[16], const uint8_t nonce[8],
                                     bool length_field, bool encrypt, const uint8_t *input, size_t length, uint8_t *out,
                                     size_t capacity)
{
    uint8_t          key[32] = {0};
    uint8_t          iv[32]  = {0};
    wcrypto_status_t status  = requestDerived(
        cmd_key, auth_id, nonce, length_field ? "VMess Header AEAD Key_Length" : "VMess Header AEAD Key", key);
    if (status == kWCryptoOk)
    {
        status = requestDerived(
            cmd_key, auth_id, nonce, length_field ? "VMess Header AEAD Nonce_Length" : "VMess Header AEAD Nonce", iv);
    }
    if (status == kWCryptoOk)
    {
        status = headerAead(key, iv, encrypt, auth_id, 16, input, length, out, capacity);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(iv, sizeof(iv));
    return status;
}

wcrypto_status_t vmessRequestLengthOpen(const uint8_t cmd_key[16], const uint8_t auth_id[16],
                                        const uint8_t encrypted_length[18], const uint8_t nonce[8],
                                        uint16_t *plaintext_length)
{
    uint8_t plain[2] = {0};
    assert(cmd_key && auth_id && encrypted_length && nonce && plaintext_length);
    wcrypto_status_t status =
        requestCrypt(cmd_key, auth_id, nonce, true, false, encrypted_length, 18, plain, sizeof(plain));
    *plaintext_length = 0;
    if (status == kWCryptoOk)
    {
        *plaintext_length = read16(plain);
        if (*plaintext_length < 45 || *plaintext_length > VMESS_REQUEST_HEADER_MAX)
        {
            status = kWCryptoInvalidArgument;
        }
    }
    wCryptoZero(plain, sizeof(plain));
    return status;
}

bool vmessModeValid(uint8_t security, uint8_t options, uint8_t command)
{
    if ((command != 1 && command != 2) ||
        (options & ~(VMESS_OPTION_CHUNK | VMESS_OPTION_MASK | VMESS_OPTION_PADDING | VMESS_OPTION_AUTH_LENGTH)) != 0)
    {
        return false;
    }
    if ((options & VMESS_OPTION_PADDING) != 0 && (options & VMESS_OPTION_MASK) == 0)
    {
        return false;
    }
    if (security == VMESS_SECURITY_NONE)
    {
        if ((options & VMESS_OPTION_AUTH_LENGTH) != 0 || (command == 1 && (options & VMESS_OPTION_PADDING) != 0))
        {
            return false;
        }
        return (options & VMESS_OPTION_CHUNK) != 0 || (command == 1 && options == 0);
    }
    return (security == VMESS_SECURITY_AES128_GCM || security == VMESS_SECURITY_CHACHA20_POLY1305) &&
           (options & VMESS_OPTION_CHUNK) != 0;
}

wcrypto_status_t vmessRequestHeaderParse(const uint8_t *plaintext, size_t length, vmess_request_header_t *out)
{
    assert(plaintext != NULL && out != NULL);
    memset(out, 0, sizeof(*out));
    if (length < 45 || length > VMESS_REQUEST_HEADER_MAX || plaintext[0] != 1 || plaintext[36] != 0 ||
        ! vmessModeValid(plaintext[35] & 15, plaintext[34], plaintext[37]) ||
        read32(plaintext + length - 4) != fnv1a32(plaintext, length - 4))
    {
        return kWCryptoInvalidArgument;
    }
    size_t pos            = 41;
    size_t address_length = plaintext[40] == 1 ? 4 : (plaintext[40] == 3 ? 16 : 0);
    if (plaintext[40] == 2)
    {
        address_length = plaintext[pos++];
    }
    size_t padding = plaintext[35] >> 4;
    if (address_length == 0 || pos + address_length + padding + 4 != length || read16(plaintext + 38) == 0)
    {
        return kWCryptoInvalidArgument;
    }
    if (plaintext[40] == 2 && memchr(plaintext + pos, 0, address_length) != NULL)
    {
        return kWCryptoInvalidArgument;
    }
    out->version = plaintext[0];
    memcpy(out->iv, plaintext + 1, 16);
    memcpy(out->key, plaintext + 17, 16);
    out->response       = plaintext[33];
    out->options        = plaintext[34];
    out->security       = plaintext[35] & 15;
    out->command        = plaintext[37];
    out->port           = read16(plaintext + 38);
    out->address_type   = plaintext[40];
    out->address_length = (uint8_t) address_length;
    memcpy(out->address, plaintext + pos, address_length);
    return kWCryptoOk;
}

wcrypto_status_t vmessRequestHeaderOpen(const uint8_t cmd_key[16], const uint8_t auth_id[16], const uint8_t nonce[8],
                                        const uint8_t *encrypted_header, size_t encrypted_length,
                                        vmess_request_header_t *out)
{
    assert(cmd_key && auth_id && nonce && encrypted_header && out);
    uint8_t plaintext[VMESS_REQUEST_HEADER_MAX] = {0};
    memset(out, 0, sizeof(*out));
    if (encrypted_length < 16 || encrypted_length > sizeof(plaintext) + 16)
    {
        return kWCryptoInvalidArgument;
    }
    wcrypto_status_t status = requestCrypt(
        cmd_key, auth_id, nonce, false, false, encrypted_header, encrypted_length, plaintext, sizeof(plaintext));
    if (status == kWCryptoOk)
    {
        status = vmessRequestHeaderParse(plaintext, encrypted_length - 16, out);
    }
    wCryptoZero(plaintext, sizeof(plaintext));
    return status;
}

wcrypto_status_t vmessRequestHeaderSeal(const uint8_t cmd_key[16], const uint8_t auth_id[16], const uint8_t nonce[8],
                                        const vmess_request_header_t *header, const uint8_t *padding,
                                        size_t padding_length, uint8_t *out, size_t capacity, size_t *wire_length)
{
    assert(cmd_key && auth_id && nonce && header && wire_length);
    assert((padding != NULL || padding_length == 0) && (out != NULL || capacity == 0));
    *wire_length = 0;
    if (header->version != 1 || header->port == 0 || padding_length > 15 ||
        ! vmessModeValid(header->security, header->options, header->command) ||
        (header->address_type == 1   ? header->address_length != 4
         : header->address_type == 3 ? header->address_length != 16
         : header->address_type == 2
             ? header->address_length == 0 || memchr(header->address, 0, header->address_length) != NULL
             : true))
    {
        return kWCryptoInvalidArgument;
    }
    size_t plain_length = 41 + (header->address_type == 2 ? 1 : 0) + header->address_length + padding_length + 4;
    size_t total_length = VMESS_REQUEST_PREFIX_SIZE + plain_length + 16;
    if (capacity < total_length)
    {
        return kWCryptoInputTooLarge;
    }
    uint8_t plain[VMESS_REQUEST_HEADER_MAX] = {0};
    plain[0]                                = 1;
    memcpy(plain + 1, header->iv, 16);
    memcpy(plain + 17, header->key, 16);
    plain[33] = header->response;
    plain[34] = header->options;
    plain[35] = (uint8_t) ((padding_length << 4) | header->security);
    plain[37] = header->command;
    write16(plain + 38, header->port);
    plain[40]  = header->address_type;
    size_t pos = 41;
    if (header->address_type == 2)
    {
        plain[pos++] = header->address_length;
    }
    memcpy(plain + pos, header->address, header->address_length);
    pos += header->address_length;
    if (padding_length != 0)
    {
        memcpy(plain + pos, padding, padding_length);
    }
    write32(plain + plain_length - 4, fnv1a32(plain, plain_length - 4));
    uint8_t length[2];
    write16(length, (uint16_t) plain_length);
    memcpy(out, auth_id, 16);
    memcpy(out + 34, nonce, 8);
    wcrypto_status_t status = requestCrypt(cmd_key, auth_id, nonce, true, true, length, sizeof(length), out + 16, 18);
    if (status == kWCryptoOk)
    {
        status = requestCrypt(cmd_key,
                              auth_id,
                              nonce,
                              false,
                              true,
                              plain,
                              plain_length,
                              out + VMESS_REQUEST_PREFIX_SIZE,
                              capacity - VMESS_REQUEST_PREFIX_SIZE);
    }
    wCryptoZero(plain, sizeof(plain));
    wCryptoZero(length, sizeof(length));
    if (status == kWCryptoOk)
    {
        *wire_length = total_length;
    }
    else
    {
        wCryptoZero(out, total_length);
    }
    return status;
}

wcrypto_status_t vmessResponseKeys(const uint8_t request_key[16], const uint8_t request_iv[16],
                                   uint8_t response_key[16], uint8_t response_iv[16])
{
    assert(request_key && request_iv && response_key && response_iv);
    uint8_t key[32] = {0};
    uint8_t iv[32]  = {0};
    bool    ok      = digest(EVP_sha256(), request_key, 16, key, 32) && digest(EVP_sha256(), request_iv, 16, iv, 32);
    memcpy(response_key, key, 16);
    memcpy(response_iv, iv, 16);
    wCryptoZero(key, sizeof(key));
    wCryptoZero(iv, sizeof(iv));
    if (! ok)
    {
        wCryptoZero(response_key, 16);
        wCryptoZero(response_iv, 16);
    }
    return ok ? kWCryptoOk : kWCryptoBackendFailed;
}

wcrypto_status_t vmessResponseHeaderSeal(const uint8_t response_key[16], const uint8_t response_iv[16],
                                         uint8_t response, uint8_t out[VMESS_RESPONSE_HEADER_SIZE])
{
    assert(response_key && response_iv && out);
    const uint8_t    length[]  = {0, 4};
    const uint8_t    payload[] = {response, 0, 0, 0};
    uint8_t          key[32]   = {0};
    uint8_t          iv[32]    = {0};
    wcrypto_status_t status    = kdfLabel(response_key, "AEAD Resp Header Len Key", key);
    if (status == kWCryptoOk)
    {
        status = kdfLabel(response_iv, "AEAD Resp Header Len IV", iv);
    }
    if (status == kWCryptoOk)
    {
        status = headerAead(key, iv, true, NULL, 0, length, sizeof(length), out, 18);
    }
    if (status == kWCryptoOk)
    {
        status = kdfLabel(response_key, "AEAD Resp Header Key", key);
    }
    if (status == kWCryptoOk)
    {
        status = kdfLabel(response_iv, "AEAD Resp Header IV", iv);
    }
    if (status == kWCryptoOk)
    {
        status = headerAead(key, iv, true, NULL, 0, payload, sizeof(payload), out + 18, 20);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(iv, sizeof(iv));
    if (status != kWCryptoOk)
    {
        wCryptoZero(out, VMESS_RESPONSE_HEADER_SIZE);
    }
    return status;
}

static wcrypto_status_t responseOpen(const uint8_t response_key[16], const uint8_t response_iv[16], bool length_field,
                                     const uint8_t *input, size_t length, uint8_t *out, size_t capacity)
{
    uint8_t          key[32] = {0};
    uint8_t          iv[32]  = {0};
    wcrypto_status_t status =
        kdfLabel(response_key, length_field ? "AEAD Resp Header Len Key" : "AEAD Resp Header Key", key);
    if (status == kWCryptoOk)
    {
        status = kdfLabel(response_iv, length_field ? "AEAD Resp Header Len IV" : "AEAD Resp Header IV", iv);
    }
    if (status == kWCryptoOk)
    {
        status = headerAead(key, iv, false, NULL, 0, input, length, out, capacity);
    }
    wCryptoZero(key, sizeof(key));
    wCryptoZero(iv, sizeof(iv));
    return status;
}

wcrypto_status_t vmessResponseLengthOpen(const uint8_t response_key[16], const uint8_t response_iv[16],
                                         const uint8_t encrypted_length[18], uint16_t *plaintext_length)
{
    assert(response_key && response_iv && encrypted_length && plaintext_length);
    *plaintext_length         = 0;
    uint8_t          plain[2] = {0};
    wcrypto_status_t status = responseOpen(response_key, response_iv, true, encrypted_length, 18, plain, sizeof(plain));
    if (status == kWCryptoOk)
    {
        uint16_t length = read16(plain);
        if (length < 4 || length > VMESS_RESPONSE_HEADER_MAX)
        {
            status = kWCryptoInvalidArgument;
        }
        else
        {
            *plaintext_length = length;
        }
    }
    wCryptoZero(plain, sizeof(plain));
    return status;
}

wcrypto_status_t vmessResponseHeaderOpen(const uint8_t response_key[16], const uint8_t response_iv[16],
                                         uint8_t expected_response, const uint8_t *encrypted_header,
                                         size_t encrypted_length)
{
    assert(response_key && response_iv && encrypted_header);
    if (encrypted_length < 20 || encrypted_length > VMESS_RESPONSE_HEADER_MAX + 16)
    {
        return kWCryptoInvalidArgument;
    }
    uint8_t          plain[VMESS_RESPONSE_HEADER_MAX] = {0};
    wcrypto_status_t status =
        responseOpen(response_key, response_iv, false, encrypted_header, encrypted_length, plain, sizeof(plain));
    if (status == kWCryptoOk && plain[0] != expected_response)
    {
        status = kWCryptoAuthenticationFailed;
    }
    if (status == kWCryptoOk && ((size_t) plain[3] + 4 != encrypted_length - 16 || (plain[2] == 0 && plain[3] != 0)))
    {
        status = kWCryptoInvalidArgument;
    }
    wCryptoZero(plain, sizeof(plain));
    return status;
}

static bool chachaKey(const uint8_t key[16], uint8_t out[32])
{
    return digest(EVP_md5(), key, 16, out, 16) && digest(EVP_md5(), out, 16, out + 16, 16);
}

static const EVP_CIPHER *bodyAlgorithm(const vmess_body_ctx_t *ctx)
{
    return ctx->security == VMESS_SECURITY_AES128_GCM ? EVP_aes_128_gcm() : EVP_chacha20_poly1305();
}

void vmessBodyDestroy(vmess_body_ctx_t *ctx)
{
    assert(ctx != NULL);
    EVP_CIPHER_CTX_free(ctx->cipher);
    EVP_CIPHER_CTX_free(ctx->length_cipher);
    EVP_MD_CTX_free(ctx->shake);
    wCryptoZero(ctx, sizeof(*ctx));
}

wcrypto_status_t vmessBodyInit(vmess_body_ctx_t *ctx, const uint8_t key[16], const uint8_t iv[16], uint8_t security,
                               uint8_t options, uint8_t command, bool encrypt)
{
    assert(ctx && key && iv && ctx->cipher == NULL && ctx->length_cipher == NULL && ctx->shake == NULL);
    if (! vmessModeValid(security, options, command))
    {
        return kWCryptoInvalidArgument;
    }
    ctx->security = security;
    ctx->options  = options;
    ctx->encrypt  = encrypt;
    ctx->raw      = security == VMESS_SECURITY_NONE && (options & VMESS_OPTION_CHUNK) == 0;
    memcpy(ctx->iv, iv, 16);
    memcpy(ctx->length_iv, iv, 16);
    memcpy(ctx->key, key, 16);
    uint8_t          derived[32] = {0};
    wcrypto_status_t status      = kWCryptoBackendFailed;
    if (security == VMESS_SECURITY_CHACHA20_POLY1305 && ! chachaKey(key, ctx->key))
    {
        goto fail;
    }
    if (security != VMESS_SECURITY_NONE)
    {
        ctx->cipher = EVP_CIPHER_CTX_new();
        if (ctx->cipher == NULL)
        {
            goto fail;
        }
    }
    if ((options & VMESS_OPTION_AUTH_LENGTH) != 0)
    {
        status = kdfLabel(key, "auth_len", derived);
        if (status != kWCryptoOk)
        {
            goto fail;
        }
        status = kWCryptoBackendFailed;
        if (security == VMESS_SECURITY_CHACHA20_POLY1305)
        {
            if (! chachaKey(derived, ctx->length_key))
            {
                goto fail;
            }
        }
        else
        {
            memcpy(ctx->length_key, derived, 16);
        }
        ctx->length_cipher = EVP_CIPHER_CTX_new();
        if (ctx->length_cipher == NULL)
        {
            goto fail;
        }
    }
    if ((options & VMESS_OPTION_MASK) != 0)
    {
        ctx->shake = EVP_MD_CTX_new();
        if (ctx->shake == NULL || EVP_DigestInit_ex(ctx->shake, EVP_shake128(), NULL) != 1 ||
            EVP_DigestUpdate(ctx->shake, iv, 16) != 1)
        {
            goto fail;
        }
    }
    wCryptoZero(derived, sizeof(derived));
    return kWCryptoOk;
fail:
    wCryptoZero(derived, sizeof(derived));
    vmessBodyDestroy(ctx);
    return status;
}

wcrypto_status_t vmessBodySetLengthMaterial(vmess_body_ctx_t *ctx, const uint8_t request_key[16],
                                            const uint8_t request_iv[16])
{
    assert(ctx && request_key && request_iv && ctx->length_cipher != NULL && ctx->counter == 0 && ! ctx->pending &&
           ! ctx->failed && ! ctx->ended);
    uint8_t          derived[32] = {0};
    wcrypto_status_t status      = kdfLabel(request_key, "auth_len", derived);
    if (status == kWCryptoOk)
    {
        if (ctx->security == VMESS_SECURITY_CHACHA20_POLY1305)
        {
            status = chachaKey(derived, ctx->length_key) ? kWCryptoOk : kWCryptoBackendFailed;
        }
        else
        {
            memcpy(ctx->length_key, derived, 16);
        }
    }
    if (status == kWCryptoOk)
    {
        memcpy(ctx->length_iv, request_iv, 16);
    }
    else
    {
        ctx->failed = true;
    }
    wCryptoZero(derived, sizeof(derived));
    return status;
}

size_t vmessBodyLengthSize(const vmess_body_ctx_t *ctx)
{
    assert(ctx != NULL);
    return ctx->raw ? 0 : ((ctx->options & VMESS_OPTION_AUTH_LENGTH) != 0 ? 18 : 2);
}

size_t vmessBodyMaxPlaintext(const vmess_body_ctx_t *ctx)
{
    assert(ctx != NULL);
    if (ctx->raw)
    {
        return UINT16_MAX;
    }
    size_t tag     = ctx->security == VMESS_SECURITY_NONE ? 0 : 16;
    size_t offset  = (ctx->options & VMESS_OPTION_AUTH_LENGTH) != 0 ? 16 : 0;
    size_t padding = (ctx->options & VMESS_OPTION_PADDING) != 0 ? 63 : 0;
    return UINT16_MAX + offset - tag - padding;
}

static bool shakeNext(vmess_body_ctx_t *ctx, uint16_t *value)
{
    uint8_t bytes[2];
    if (EVP_DigestSqueeze(ctx->shake, bytes, sizeof(bytes)) != 1)
    {
        return false;
    }
    *value = read16(bytes);
    return true;
}

static void bodyNonce(const vmess_body_ctx_t *ctx, uint8_t nonce[12])
{
    memcpy(nonce, ctx->iv, 12);
    write16(nonce, (uint16_t) ctx->counter);
}

static wcrypto_status_t bodyFail(vmess_body_ctx_t *ctx, wcrypto_status_t status)
{
    ctx->failed = true;
    return status;
}

wcrypto_status_t vmessBodyLengthOpen(vmess_body_ctx_t *ctx, const uint8_t *prefix, size_t prefix_length,
                                     uint32_t *body_wire_length)
{
    assert(ctx && prefix && body_wire_length && ! ctx->encrypt && ! ctx->raw && ! ctx->pending);
    *body_wire_length = 0;
    if (ctx->failed || ctx->ended)
    {
        return kWCryptoInvalidState;
    }
    if (ctx->security != VMESS_SECURITY_NONE && ctx->counter > UINT16_MAX)
    {
        return bodyFail(ctx, kVmessCounterExhausted);
    }
    if (prefix_length != vmessBodyLengthSize(ctx))
    {
        return bodyFail(ctx, kWCryptoInvalidArgument);
    }
    uint16_t padding = 0;
    if ((ctx->options & VMESS_OPTION_PADDING) != 0)
    {
        if (! shakeNext(ctx, &padding))
        {
            return bodyFail(ctx, kWCryptoBackendFailed);
        }
        padding %= 64;
    }
    uint32_t size = 0;
    if ((ctx->options & VMESS_OPTION_AUTH_LENGTH) != 0)
    {
        uint8_t nonce[12];
        uint8_t plain[2] = {0};
        memcpy(nonce, ctx->length_iv, sizeof(nonce));
        write16(nonce, (uint16_t) ctx->counter);
        wcrypto_status_t status = aead(ctx->length_cipher,
                                       bodyAlgorithm(ctx),
                                       false,
                                       ctx->length_key,
                                       nonce,
                                       NULL,
                                       0,
                                       prefix,
                                       18,
                                       plain,
                                       sizeof(plain));
        if (status != kWCryptoOk)
        {
            return bodyFail(ctx, status);
        }
        /* Add in a wide type: 65535 encodes a 65551-byte body. */
        size = (uint32_t) read16(plain) + 16U;
        wCryptoZero(plain, sizeof(plain));
    }
    else
    {
        uint16_t mask = 0;
        if ((ctx->options & VMESS_OPTION_MASK) != 0 && ! shakeNext(ctx, &mask))
        {
            return bodyFail(ctx, kWCryptoBackendFailed);
        }
        size = read16(prefix) ^ mask;
    }
    uint32_t tag = ctx->security == VMESS_SECURITY_NONE ? 0 : 16;
    if (size < (uint32_t) padding + tag || size > VMESS_MAX_BODY_WIRE_SIZE)
    {
        return bodyFail(ctx, kWCryptoInvalidArgument);
    }
    ctx->pending             = true;
    ctx->pending_wire_length = size;
    ctx->pending_padding     = padding;
    *body_wire_length        = size;
    return kWCryptoOk;
}

wcrypto_status_t vmessBodyOpen(vmess_body_ctx_t *ctx, const uint8_t *body, size_t body_length, uint8_t *out,
                               size_t capacity, size_t *plaintext_length, bool *eof)
{
    assert(ctx && plaintext_length && eof && ! ctx->encrypt && ! ctx->raw && ctx->pending);
    assert((body != NULL || body_length == 0) && (out != NULL || capacity == 0));
    *plaintext_length = 0;
    *eof              = false;
    if (ctx->failed || ctx->ended || body_length != ctx->pending_wire_length)
    {
        return bodyFail(ctx, kWCryptoInvalidState);
    }
    size_t tag              = ctx->security == VMESS_SECURITY_NONE ? 0 : 16;
    size_t encrypted_length = body_length - ctx->pending_padding;
    size_t plain_length     = encrypted_length - tag;
    if (capacity < plain_length)
    {
        return bodyFail(ctx, kWCryptoInputTooLarge);
    }
    if (tag != 0)
    {
        uint8_t nonce[12];
        bodyNonce(ctx, nonce);
        wcrypto_status_t status = aead(
            ctx->cipher, bodyAlgorithm(ctx), false, ctx->key, nonce, NULL, 0, body, encrypted_length, out, capacity);
        if (status != kWCryptoOk)
        {
            return bodyFail(ctx, status);
        }
        ++ctx->counter;
    }
    else if (plain_length != 0)
    {
        memmove(out, body, plain_length);
    }
    ctx->pending      = false;
    ctx->ended        = plain_length == 0;
    *eof              = ctx->ended;
    *plaintext_length = plain_length;
    return kWCryptoOk;
}

wcrypto_status_t vmessBodySeal(vmess_body_ctx_t *ctx, const uint8_t *plaintext, size_t plaintext_length, bool eof,
                               uint8_t *out, size_t capacity, size_t *wire_length)
{
    assert(ctx && wire_length && ctx->encrypt && (plaintext != NULL || plaintext_length == 0));
    assert(out != NULL || capacity == 0);
    *wire_length = 0;
    if (ctx->failed || ctx->ended)
    {
        return kWCryptoInvalidState;
    }
    if ((eof && plaintext_length != 0) || (! eof && plaintext_length == 0))
    {
        return kWCryptoInvalidArgument;
    }
    if (ctx->raw)
    {
        if (capacity < plaintext_length)
        {
            return kWCryptoInputTooLarge;
        }
        if (plaintext_length != 0)
        {
            memmove(out, plaintext, plaintext_length);
        }
        ctx->ended   = eof;
        *wire_length = plaintext_length;
        return kWCryptoOk;
    }
    size_t tag = ctx->security == VMESS_SECURITY_NONE ? 0 : 16;
    if (tag != 0 && (ctx->counter > UINT16_MAX || (! eof && ctx->counter == UINT16_MAX)))
    {
        return kVmessCounterExhausted;
    }
    size_t prefix_length = vmessBodyLengthSize(ctx);
    size_t max_padding   = (ctx->options & VMESS_OPTION_PADDING) != 0 ? 63 : 0;
    if (plaintext_length > vmessBodyMaxPlaintext(ctx) ||
        capacity < prefix_length + plaintext_length + tag + max_padding)
    {
        return kWCryptoInputTooLarge;
    }
    uint16_t padding = 0;
    if ((ctx->options & VMESS_OPTION_PADDING) != 0)
    {
        if (! shakeNext(ctx, &padding))
        {
            return bodyFail(ctx, kWCryptoBackendFailed);
        }
        padding %= 64;
    }
    size_t  body_length = plaintext_length + tag + padding;
    uint8_t nonce[12];
    bodyNonce(ctx, nonce);
    wcrypto_status_t status = kWCryptoOk;
    if ((ctx->options & VMESS_OPTION_AUTH_LENGTH) != 0)
    {
        uint8_t length[2];
        uint8_t length_nonce[12];
        memcpy(length_nonce, ctx->length_iv, sizeof(length_nonce));
        write16(length_nonce, (uint16_t) ctx->counter);
        write16(length, (uint16_t) (body_length - 16));
        status = aead(ctx->length_cipher,
                      bodyAlgorithm(ctx),
                      true,
                      ctx->length_key,
                      length_nonce,
                      NULL,
                      0,
                      length,
                      sizeof(length),
                      out,
                      capacity);
    }
    else
    {
        uint16_t mask = 0;
        if ((ctx->options & VMESS_OPTION_MASK) != 0 && ! shakeNext(ctx, &mask))
        {
            return bodyFail(ctx, kWCryptoBackendFailed);
        }
        write16(out, (uint16_t) body_length ^ mask);
    }
    if (status == kWCryptoOk)
    {
        if (tag != 0)
        {
            status = aead(ctx->cipher,
                          bodyAlgorithm(ctx),
                          true,
                          ctx->key,
                          nonce,
                          NULL,
                          0,
                          plaintext,
                          plaintext_length,
                          out + prefix_length,
                          capacity - prefix_length);
        }
        else if (plaintext_length != 0)
        {
            memcpy(out + prefix_length, plaintext, plaintext_length);
        }
    }
    if (status != kWCryptoOk)
    {
        wCryptoZero(out, prefix_length + body_length);
        return bodyFail(ctx, status);
    }
    if (padding != 0)
    {
        getRandomBytes(out + prefix_length + plaintext_length + tag, padding);
    }
    if (tag != 0)
    {
        ++ctx->counter;
    }
    ctx->ended   = eof;
    *wire_length = prefix_length + body_length;
    return kWCryptoOk;
}
