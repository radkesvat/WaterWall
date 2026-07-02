#include "quic_sniffing.h"

#include "generic_sniffer.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#define ROUTER_QUIC_VERSION_1       0x00000001U
#define ROUTER_QUIC_VERSION_DRAFT29 0xff00001dU

enum
{
    kRouterQuicCryptoMax             = kGenericSnifferMaxWindowBytes,
    kRouterQuicInitialSaltLength     = 20U,
    kRouterQuicInitialSecretLength   = 32U,
    kRouterQuicAes128KeyLength       = 16U,
    kRouterQuicAes128BlockLength     = 16U,
    kRouterQuicIvLength              = 12U,
    kRouterQuicAeadTagLength         = 16U,
    kRouterQuicMaxConnectionIdLength = 20U,
};

typedef enum router_quic_tls_parse_e
{
    kRouterQuicTlsParseOk       = 0,
    kRouterQuicTlsParseNeedMore = 1,
    kRouterQuicTlsParseNoSni    = 2,
    kRouterQuicTlsParseBad      = 3
} router_quic_tls_parse_t;

static const uint8_t kRouterQuicSaltV1[kRouterQuicInitialSaltLength] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

static const uint8_t kRouterQuicSaltDraft29[kRouterQuicInitialSaltLength] = {
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
    0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99,
};

static router_quic_sni_result_t routerQuicNeedMoreOrMissing(uint32_t payload_len)
{
    return payload_len < (uint32_t) kGenericSnifferMaxWindowBytes ? kRouterQuicSniNeedMore : kRouterQuicSniMissing;
}

static bool routerQuicReadVarint(const uint8_t *payload, size_t payload_len, size_t *offset, uint64_t *value,
                                  size_t *encoded_len)
{
    if (*offset >= payload_len)
    {
        return false;
    }

    uint8_t first = payload[*offset];
    size_t  len   = (size_t) 1U << (first >> 6U);
    if (*offset + len > payload_len)
    {
        return false;
    }

    uint64_t decoded = first & 0x3fU;
    for (size_t i = 1U; i < len; ++i)
    {
        decoded = (decoded << 8U) | payload[*offset + i];
    }

    *offset += len;
    *value = decoded;
    if (encoded_len != NULL)
    {
        *encoded_len = len;
    }
    return true;
}

static bool routerQuicHkdfExtractSha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                                        uint8_t out[kRouterQuicInitialSecretLength])
{
    unsigned int out_len = 0;
    if (HMAC(EVP_sha256(), salt, (int) salt_len, ikm, ikm_len, out, &out_len) == NULL)
    {
        return false;
    }
    return out_len == kRouterQuicInitialSecretLength;
}

static bool routerQuicHkdfExpandSha256(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len,
                                       uint8_t *out, size_t out_len)
{
    uint8_t t[EVP_MAX_MD_SIZE];
    size_t  t_len   = 0;
    size_t  written = 0;
    uint8_t counter = 1;

    if (out_len > 255U * kRouterQuicInitialSecretLength)
    {
        return false;
    }

    while (written < out_len)
    {
        uint8_t input[EVP_MAX_MD_SIZE + 256U + 1U];
        if (t_len + info_len + 1U > sizeof(input))
        {
            return false;
        }

        memoryCopy(input, t, t_len);
        memoryCopy(input + t_len, info, info_len);
        input[t_len + info_len] = counter;

        unsigned int md_len = 0;
        if (HMAC(EVP_sha256(), prk, (int) prk_len, input, t_len + info_len + 1U, t, &md_len) == NULL)
        {
            return false;
        }
        if (md_len != kRouterQuicInitialSecretLength)
        {
            return false;
        }

        size_t take = out_len - written;
        if (take > md_len)
        {
            take = md_len;
        }
        memoryCopy(out + written, t, take);
        written += take;
        t_len = md_len;
        ++counter;
    }

    memoryZero(t, sizeof(t));
    return true;
}

static bool routerQuicHkdfExpandLabelSha256(const uint8_t *secret, size_t secret_len, const char *label, uint8_t *out,
                                            size_t out_len)
{
    static const char kTls13LabelPrefix[] = "tls13 ";

    uint8_t info[256];
    size_t  prefix_len = stringLength(kTls13LabelPrefix);
    size_t  label_len  = stringLength(label);
    size_t  full_len   = prefix_len + label_len;
    size_t  info_len   = 2U + 1U + full_len + 1U;

    if (out_len > UINT16_MAX || full_len > UINT8_MAX || info_len > sizeof(info))
    {
        return false;
    }

    PUT_BE16(info, (uint16_t) out_len);
    info[2] = (uint8_t) full_len;
    memoryCopy(info + 3U, kTls13LabelPrefix, prefix_len);
    memoryCopy(info + 3U + prefix_len, label, label_len);
    info[3U + full_len] = 0U;

    return routerQuicHkdfExpandSha256(secret, secret_len, info, info_len, out, out_len);
}

static bool routerQuicAes128EncryptBlock(const uint8_t key[kRouterQuicAes128KeyLength],
                                         const uint8_t input[kRouterQuicAes128BlockLength],
                                         uint8_t       output[kRouterQuicAes128BlockLength])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    int len1 = 0;
    int len2 = 0;
    bool ok  = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
              EVP_EncryptUpdate(ctx, output, &len1, input, kRouterQuicAes128BlockLength) == 1 &&
              EVP_EncryptFinal_ex(ctx, output + len1, &len2) == 1 && len1 + len2 == kRouterQuicAes128BlockLength;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool routerQuicAes128GcmOpen(const uint8_t key[kRouterQuicAes128KeyLength],
                                    const uint8_t nonce[kRouterQuicIvLength], const uint8_t *aad, size_t aad_len,
                                    const uint8_t *ciphertext_and_tag, size_t ciphertext_and_tag_len,
                                    uint8_t *plaintext, size_t *plaintext_len)
{
    if (ciphertext_and_tag_len < kRouterQuicAeadTagLength)
    {
        return false;
    }

    size_t ciphertext_len = ciphertext_and_tag_len - kRouterQuicAeadTagLength;
    const uint8_t *tag    = ciphertext_and_tag + ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return false;
    }

    int len     = 0;
    int out_len = 0;
    bool ok     = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kRouterQuicIvLength, NULL) == 1 &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;

    if (ok && aad_len > 0)
    {
        ok = EVP_DecryptUpdate(ctx, NULL, &len, aad, (int) aad_len) == 1;
    }
    if (ok && ciphertext_len > 0)
    {
        ok      = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext_and_tag, (int) ciphertext_len) == 1;
        out_len = len;
    }
    if (ok)
    {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kRouterQuicAeadTagLength, (void *) tag) == 1 &&
             EVP_DecryptFinal_ex(ctx, plaintext + out_len, &len) == 1;
        out_len += len;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (! ok)
    {
        return false;
    }

    *plaintext_len = (size_t) out_len;
    return true;
}

static void routerQuicTrimHost(const uint8_t **host, uint32_t *host_len)
{
    while (*host_len > 0 &&
           ((*host)[*host_len - 1U] == ' ' || (*host)[*host_len - 1U] == '\t' || (*host)[*host_len - 1U] == '\r'))
    {
        *host_len -= 1U;
    }

    while (*host_len > 0 && (*host)[*host_len - 1U] == '.')
    {
        *host_len -= 1U;
    }
}

static router_quic_tls_parse_t routerQuicParseTlsClientHelloSni(const uint8_t *payload, size_t payload_len,
                                                                uint8_t *host, uint32_t host_cap,
                                                                uint32_t *host_len)
{
    if (payload_len < 4U)
    {
        return kRouterQuicTlsParseNeedMore;
    }
    if (payload[0] != 0x01U)
    {
        return kRouterQuicTlsParseBad;
    }

    uint32_t handshake_len = GET_BE24(payload + 1U);
    if (payload_len < 4U + (size_t) handshake_len)
    {
        return kRouterQuicTlsParseNeedMore;
    }

    size_t offset = 4U;
    size_t end    = 4U + (size_t) handshake_len;

    if (end < offset + 2U + 32U + 1U)
    {
        return kRouterQuicTlsParseBad;
    }
    offset += 2U + 32U;

    uint8_t session_id_len = payload[offset++];
    if (end < offset + session_id_len + 2U)
    {
        return kRouterQuicTlsParseBad;
    }
    offset += session_id_len;

    uint16_t cipher_suites_len = GET_BE16(payload + offset);
    offset += 2U;
    if (end < offset + cipher_suites_len + 1U)
    {
        return kRouterQuicTlsParseBad;
    }
    offset += cipher_suites_len;

    uint8_t compression_methods_len = payload[offset++];
    if (end < offset + compression_methods_len)
    {
        return kRouterQuicTlsParseBad;
    }
    offset += compression_methods_len;

    if (offset == end)
    {
        return kRouterQuicTlsParseNoSni;
    }
    if (end < offset + 2U)
    {
        return kRouterQuicTlsParseBad;
    }

    uint16_t extensions_len = GET_BE16(payload + offset);
    offset += 2U;
    if (end < offset + extensions_len)
    {
        return kRouterQuicTlsParseBad;
    }

    size_t extensions_end = offset + extensions_len;
    while (offset + 4U <= extensions_end)
    {
        uint16_t extension_type = GET_BE16(payload + offset);
        uint16_t extension_len  = GET_BE16(payload + offset + 2U);
        offset += 4U;
        if (offset + extension_len > extensions_end)
        {
            return kRouterQuicTlsParseBad;
        }

        if (extension_type == 0x0000U)
        {
            const uint8_t *extension = payload + offset;
            if (extension_len < 2U)
            {
                return kRouterQuicTlsParseBad;
            }

            uint16_t server_name_list_len = GET_BE16(extension);
            size_t   name_offset          = 2U;
            size_t   name_end             = 2U + (size_t) server_name_list_len;
            if (name_end > extension_len)
            {
                return kRouterQuicTlsParseBad;
            }

            while (name_offset + 3U <= name_end)
            {
                uint8_t  name_type = extension[name_offset++];
                uint16_t name_len  = GET_BE16(extension + name_offset);
                name_offset += 2U;
                if (name_offset + name_len > name_end)
                {
                    return kRouterQuicTlsParseBad;
                }

                if (name_type == 0x00U)
                {
                    const uint8_t *value     = extension + name_offset;
                    uint32_t       value_len = name_len;
                    routerQuicTrimHost(&value, &value_len);

                    if (value_len == 0 || value_len >= host_cap)
                    {
                        return kRouterQuicTlsParseNoSni;
                    }

                    memoryCopy(host, value, value_len);
                    host[value_len] = '\0';
                    *host_len       = value_len;
                    return kRouterQuicTlsParseOk;
                }

                name_offset += name_len;
            }

            return kRouterQuicTlsParseNoSni;
        }

        offset += extension_len;
    }

    return offset == extensions_end ? kRouterQuicTlsParseNoSni : kRouterQuicTlsParseBad;
}

static bool routerQuicMarkCrypto(uint8_t *crypto, uint8_t *seen, size_t *max_crypto_end, uint64_t crypto_offset,
                                 uint64_t crypto_len, const uint8_t *src, size_t src_len)
{
    if (crypto_len > src_len)
    {
        return false;
    }
    if (crypto_offset > kRouterQuicCryptoMax || crypto_len > kRouterQuicCryptoMax - crypto_offset)
    {
        return false;
    }

    memoryCopy(crypto + crypto_offset, src, (size_t) crypto_len);
    memorySet(seen + crypto_offset, 1, (size_t) crypto_len);

    size_t crypto_end = (size_t) (crypto_offset + crypto_len);
    if (*max_crypto_end < crypto_end)
    {
        *max_crypto_end = crypto_end;
    }
    return true;
}

static size_t routerQuicContiguousCryptoLength(const uint8_t *seen, size_t max_crypto_end)
{
    size_t len = 0;
    while (len < max_crypto_end && seen[len] != 0)
    {
        ++len;
    }
    return len;
}

static bool routerQuicSkipAckFrame(const uint8_t *payload, size_t payload_len, size_t *offset, bool has_ecn)
{
    uint64_t value            = 0;
    uint64_t ack_range_count  = 0;
    uint64_t reasonless_count = has_ecn ? 3U : 0U;

    if (! routerQuicReadVarint(payload, payload_len, offset, &value, NULL) ||
        ! routerQuicReadVarint(payload, payload_len, offset, &value, NULL) ||
        ! routerQuicReadVarint(payload, payload_len, offset, &ack_range_count, NULL) ||
        ! routerQuicReadVarint(payload, payload_len, offset, &value, NULL))
    {
        return false;
    }

    for (uint64_t i = 0; i < ack_range_count; ++i)
    {
        if (! routerQuicReadVarint(payload, payload_len, offset, &value, NULL) ||
            ! routerQuicReadVarint(payload, payload_len, offset, &value, NULL))
        {
            return false;
        }
    }

    for (uint64_t i = 0; i < reasonless_count; ++i)
    {
        if (! routerQuicReadVarint(payload, payload_len, offset, &value, NULL))
        {
            return false;
        }
    }

    return true;
}

static bool routerQuicParseInitialFrames(const uint8_t *payload, size_t payload_len, uint8_t *crypto, uint8_t *seen,
                                         size_t *max_crypto_end)
{
    size_t offset = 0;

    while (offset < payload_len)
    {
        uint8_t frame_type = payload[offset++];

        switch (frame_type)
        {
        case 0x00U: // PADDING
        case 0x01U: // PING
            break;
        case 0x02U: // ACK
        case 0x03U: // ACK with ECN
            if (! routerQuicSkipAckFrame(payload, payload_len, &offset, frame_type == 0x03U))
            {
                return false;
            }
            break;
        case 0x06U: { // CRYPTO
            uint64_t crypto_offset = 0;
            uint64_t crypto_len    = 0;
            if (! routerQuicReadVarint(payload, payload_len, &offset, &crypto_offset, NULL) ||
                ! routerQuicReadVarint(payload, payload_len, &offset, &crypto_len, NULL))
            {
                return false;
            }
            if (crypto_len > payload_len - offset)
            {
                return false;
            }
            if (! routerQuicMarkCrypto(crypto, seen, max_crypto_end, crypto_offset, crypto_len, payload + offset,
                                       payload_len - offset))
            {
                return false;
            }
            offset += (size_t) crypto_len;
            break;
        }
        case 0x1cU: { // CONNECTION_CLOSE
            uint64_t value      = 0;
            uint64_t reason_len = 0;
            if (! routerQuicReadVarint(payload, payload_len, &offset, &value, NULL) ||
                ! routerQuicReadVarint(payload, payload_len, &offset, &value, NULL) ||
                ! routerQuicReadVarint(payload, payload_len, &offset, &reason_len, NULL))
            {
                return false;
            }
            if (reason_len > payload_len - offset)
            {
                return false;
            }
            offset += (size_t) reason_len;
            break;
        }
        default:
            return false;
        }
    }

    return true;
}

router_quic_sni_result_t routerQuicSniffClientHelloSni(const uint8_t *payload, uint32_t payload_len, uint8_t *host,
                                                       uint32_t host_cap, uint32_t *host_len)
{
    if (payload == NULL || host == NULL || host_cap == 0 || host_len == NULL)
    {
        return kRouterQuicSniMissing;
    }
    if (payload_len == 0)
    {
        return routerQuicNeedMoreOrMissing(payload_len);
    }

    host[0]   = '\0';
    *host_len = 0;

    uint8_t                 *crypto         = NULL;
    uint8_t                 *seen           = NULL;
    router_quic_sni_result_t result         = kRouterQuicSniMissing;
    size_t                   max_crypto_end = 0;
    bool                     saw_initial    = false;
    size_t                   pos            = 0;

    while (pos < payload_len)
    {
        const uint8_t *packet_start = payload + pos;
        size_t         available    = payload_len - pos;
        size_t         offset       = 0;

        if (available < 7U)
        {
            if (! saw_initial)
            {
                result = kRouterQuicSniMissing;
            }
            break;
        }

        uint8_t first = packet_start[offset++];
        if ((first & 0x80U) == 0 || (first & 0x40U) == 0)
        {
            result = saw_initial ? routerQuicNeedMoreOrMissing(payload_len) : kRouterQuicSniMissing;
            break;
        }

        uint32_t version = GET_BE32(packet_start + offset);
        offset += 4U;
        if (version != ROUTER_QUIC_VERSION_1 && version != ROUTER_QUIC_VERSION_DRAFT29)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        const uint8_t *salt = version == ROUTER_QUIC_VERSION_1 ? kRouterQuicSaltV1 : kRouterQuicSaltDraft29;

        bool is_initial = ((first & 0x30U) >> 4U) == 0x00U;

        if (offset >= available)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        uint8_t dcid_len = packet_start[offset++];
        if (dcid_len > kRouterQuicMaxConnectionIdLength || offset + dcid_len > available)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        const uint8_t *dcid = packet_start + offset;
        offset += dcid_len;

        if (offset >= available)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        uint8_t scid_len = packet_start[offset++];
        if (scid_len > kRouterQuicMaxConnectionIdLength || offset + scid_len > available)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        offset += scid_len;

        if (is_initial)
        {
            uint64_t token_len = 0;
            if (! routerQuicReadVarint(packet_start, available, &offset, &token_len, NULL) ||
                token_len > available - offset)
            {
                result = kRouterQuicSniMissing;
                break;
            }
            offset += (size_t) token_len;
        }

        uint64_t protected_packet_len64 = 0;
        if (! routerQuicReadVarint(packet_start, available, &offset, &protected_packet_len64, NULL))
        {
            break;
        }
        if (protected_packet_len64 < 4U || protected_packet_len64 > available - offset)
        {
            result = kRouterQuicSniMissing;
            break;
        }

        size_t pn_offset  = offset;
        size_t packet_len = (size_t) protected_packet_len64;
        size_t packet_end = pn_offset + packet_len;
        size_t next_pos   = pos + packet_end;

        if (! is_initial)
        {
            pos = next_pos;
            continue;
        }
        saw_initial = true;

        if (pn_offset + 4U + kRouterQuicAes128BlockLength > packet_end)
        {
            result = kRouterQuicSniMissing;
            break;
        }

        uint8_t initial_secret[kRouterQuicInitialSecretLength];
        uint8_t client_secret[kRouterQuicInitialSecretLength];
        uint8_t hp[kRouterQuicAes128KeyLength];
        uint8_t key[kRouterQuicAes128KeyLength];
        uint8_t iv[kRouterQuicIvLength];
        uint8_t mask[kRouterQuicAes128BlockLength];

        if (! routerQuicHkdfExtractSha256(salt, kRouterQuicInitialSaltLength, dcid, dcid_len, initial_secret) ||
            ! routerQuicHkdfExpandLabelSha256(initial_secret, sizeof(initial_secret), "client in", client_secret,
                                              sizeof(client_secret)) ||
            ! routerQuicHkdfExpandLabelSha256(client_secret, sizeof(client_secret), "quic hp", hp, sizeof(hp)) ||
            ! routerQuicHkdfExpandLabelSha256(client_secret, sizeof(client_secret), "quic key", key, sizeof(key)) ||
            ! routerQuicHkdfExpandLabelSha256(client_secret, sizeof(client_secret), "quic iv", iv, sizeof(iv)))
        {
            result = kRouterQuicSniMissing;
            break;
        }

        uint8_t *packet = memoryAllocate(packet_end);
        if (packet == NULL)
        {
            result = kRouterQuicSniMissing;
            break;
        }
        memoryCopy(packet, packet_start, packet_end);

        if (! routerQuicAes128EncryptBlock(hp, packet + pn_offset + 4U, mask))
        {
            memoryFree(packet);
            result = kRouterQuicSniMissing;
            break;
        }

        packet[0] ^= mask[0] & 0x0fU;
        size_t pn_len = (size_t) ((packet[0] & 0x03U) + 1U);
        if (pn_offset + pn_len > packet_end)
        {
            memoryFree(packet);
            result = kRouterQuicSniMissing;
            break;
        }

        uint64_t packet_number = 0;
        for (size_t i = 0; i < pn_len; ++i)
        {
            packet[pn_offset + i] ^= mask[i + 1U];
            packet_number = (packet_number << 8U) | packet[pn_offset + i];
        }

        uint8_t nonce[kRouterQuicIvLength];
        memoryCopy(nonce, iv, sizeof(nonce));
        for (size_t i = 0; i < 8U; ++i)
        {
            nonce[4U + i] ^= (uint8_t) (packet_number >> (56U - 8U * i));
        }

        size_t aad_len             = pn_offset + pn_len;
        size_t ciphertext_tag_len  = packet_end - aad_len;
        uint8_t *decrypted_payload = memoryAllocate(ciphertext_tag_len);
        if (decrypted_payload == NULL)
        {
            memoryFree(packet);
            result = kRouterQuicSniMissing;
            break;
        }

        size_t decrypted_payload_len = 0;
        if (! routerQuicAes128GcmOpen(key, nonce, packet, aad_len, packet + aad_len, ciphertext_tag_len,
                                      decrypted_payload, &decrypted_payload_len))
        {
            memoryFree(decrypted_payload);
            memoryFree(packet);
            result = kRouterQuicSniMissing;
            break;
        }

        if (crypto == NULL)
        {
            crypto = memoryAllocateZero(kRouterQuicCryptoMax);
            seen   = memoryAllocateZero(kRouterQuicCryptoMax);
            if (crypto == NULL || seen == NULL)
            {
                memoryFree(crypto);
                memoryFree(seen);
                crypto = NULL;
                seen   = NULL;
                memoryFree(decrypted_payload);
                memoryFree(packet);
                result = kRouterQuicSniMissing;
                break;
            }
        }

        bool frames_ok =
            routerQuicParseInitialFrames(decrypted_payload, decrypted_payload_len, crypto, seen, &max_crypto_end);
        memoryFree(decrypted_payload);
        memoryFree(packet);
        if (! frames_ok)
        {
            result = kRouterQuicSniMissing;
            break;
        }

        size_t contiguous_crypto_len = routerQuicContiguousCryptoLength(seen, max_crypto_end);
        switch (routerQuicParseTlsClientHelloSni(crypto, contiguous_crypto_len, host, host_cap, host_len))
        {
        case kRouterQuicTlsParseOk:
            result = kRouterQuicSniFound;
            goto cleanup;
        case kRouterQuicTlsParseNeedMore:
            result = routerQuicNeedMoreOrMissing(payload_len);
            break;
        case kRouterQuicTlsParseNoSni:
        case kRouterQuicTlsParseBad:
        default:
            result = kRouterQuicSniMissing;
            goto cleanup;
        }

        pos = next_pos;
    }

cleanup:
    memoryFree(crypto);
    memoryFree(seen);
    return result;
}
