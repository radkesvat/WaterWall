#include "structure.h"

enum
{
    kTlsRecordHeaderSize       = 5,
    kTlsHandshakeHeaderSize    = 4,
    kTlsRecordHandshake        = 0x16,
    kTlsRecordChangeCipherSpec = 0x14,
    kTlsRecordAlert            = 0x15,
    kTlsRecordApplicationData  = 0x17,
    kTlsHandshakeClientHello   = 0x01,
    kTlsHandshakeServerHello   = 0x02,
    kTlsExtensionSupportedVersions = 0x002b,
    kTlsMaximumRecordBody      = 16384,
    kTlsMaximumHelloBody       = 65535,
};

static const uint8_t kTls13HelloRetryRequestRandom[kRealityV2TlsRandomSize] = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

static uint16_t realityserverReadBe16(const uint8_t *data)
{
    return (uint16_t) (((uint16_t) data[0] << 8) | data[1]);
}

static bool realityserverTake(const uint8_t **cursor, size_t *remaining, size_t count, const uint8_t **out)
{
    if (count > *remaining)
    {
        return false;
    }

    if (out != NULL)
    {
        *out = *cursor;
    }
    *cursor += count;
    *remaining -= count;
    return true;
}

static bool realityserverParseExtensions(const uint8_t *data, size_t len, bool server_hello,
                                         uint16_t *selected_version)
{
    if (len == 0)
    {
        return true;
    }
    if (len < 2)
    {
        return false;
    }

    uint16_t extensions_len = realityserverReadBe16(data);
    data += 2;
    len -= 2;
    if (extensions_len != len)
    {
        return false;
    }

    bool supported_versions_seen = false;
    while (len > 0)
    {
        if (len < 4)
        {
            return false;
        }

        uint16_t extension_type = realityserverReadBe16(data);
        uint16_t extension_len  = realityserverReadBe16(data + 2);
        data += 4;
        len -= 4;
        if (extension_len > len)
        {
            return false;
        }

        if (server_hello && extension_type == kTlsExtensionSupportedVersions)
        {
            if (supported_versions_seen || extension_len != 2)
            {
                return false;
            }
            *selected_version       = realityserverReadBe16(data);
            supported_versions_seen = true;
        }

        data += extension_len;
        len -= extension_len;
    }
    return true;
}

static bool realityserverParseClientHello(const uint8_t *body, size_t len,
                                          realityserver_tls_capture_t *capture)
{
    const uint8_t *cursor    = body;
    size_t         remaining = len;
    const uint8_t *legacy_version;
    const uint8_t *random;
    const uint8_t *length_field;

    if (! realityserverTake(&cursor, &remaining, 2, &legacy_version) ||
        ! realityserverTake(&cursor, &remaining, kRealityV2TlsRandomSize, &random) ||
        ! realityserverTake(&cursor, &remaining, 1, &length_field))
    {
        return false;
    }

    uint8_t session_id_len = length_field[0];
    if (session_id_len > 32 || ! realityserverTake(&cursor, &remaining, session_id_len, NULL) ||
        ! realityserverTake(&cursor, &remaining, 2, &length_field))
    {
        return false;
    }

    uint16_t cipher_suites_len = realityserverReadBe16(length_field);
    if (cipher_suites_len < 2 || (cipher_suites_len & 1U) != 0 ||
        ! realityserverTake(&cursor, &remaining, cipher_suites_len, NULL) ||
        ! realityserverTake(&cursor, &remaining, 1, &length_field))
    {
        return false;
    }

    uint8_t compression_methods_len = length_field[0];
    if (compression_methods_len == 0 ||
        ! realityserverTake(&cursor, &remaining, compression_methods_len, NULL) ||
        ! realityserverParseExtensions(cursor, remaining, false, NULL))
    {
        return false;
    }

    capture->client_legacy_version = realityserverReadBe16(legacy_version);
    if (capture->client_legacy_version < 0x0301 || capture->client_legacy_version > 0x0303)
    {
        capture->client_legacy_version = 0;
        return false;
    }
    memoryCopy(capture->binding.client_random, random, kRealityV2TlsRandomSize);
    capture->client_ready = true;
    return true;
}

static bool realityserverParseServerHello(const uint8_t *body, size_t len,
                                          realityserver_tls_capture_t *capture, bool *hello_retry_request)
{
    const uint8_t *cursor    = body;
    size_t         remaining = len;
    const uint8_t *legacy_version;
    const uint8_t *random;
    const uint8_t *length_field;
    const uint8_t *cipher_suite;
    const uint8_t *compression_method;

    if (! realityserverTake(&cursor, &remaining, 2, &legacy_version) ||
        ! realityserverTake(&cursor, &remaining, kRealityV2TlsRandomSize, &random) ||
        ! realityserverTake(&cursor, &remaining, 1, &length_field))
    {
        return false;
    }

    uint8_t session_id_len = length_field[0];
    if (session_id_len > 32 || ! realityserverTake(&cursor, &remaining, session_id_len, NULL) ||
        ! realityserverTake(&cursor, &remaining, 2, &cipher_suite) ||
        ! realityserverTake(&cursor, &remaining, 1, &compression_method))
    {
        return false;
    }

    uint16_t selected_version = realityserverReadBe16(legacy_version);
    if (compression_method[0] != 0 ||
        ! realityserverParseExtensions(cursor, remaining, true, &selected_version))
    {
        return false;
    }

    uint16_t selected_cipher = realityserverReadBe16(cipher_suite);
    if (selected_version < 0x0301 || selected_version > 0x0304 || selected_cipher == 0)
    {
        return false;
    }

    *hello_retry_request =
        wCryptoEqual(random, kTls13HelloRetryRequestRandom, sizeof(kTls13HelloRetryRequestRandom));
    if (*hello_retry_request)
    {
        return true;
    }

    capture->binding.tls_version  = selected_version;
    capture->binding.cipher_suite = selected_cipher;

    memoryCopy(capture->binding.server_random, random, kRealityV2TlsRandomSize);
    capture->server_ready = true;
    return true;
}

static void realityserverTlsParserResetHandshake(realityserver_tls_parser_t *parser)
{
    if (parser->handshake_body != NULL)
    {
        memoryZero(parser->handshake_body, parser->handshake_length);
        memoryFree(parser->handshake_body);
        parser->handshake_body = NULL;
    }

    parser->handshake_header_length = 0;
    parser->handshake_type          = 0;
    parser->handshake_length        = 0;
    parser->handshake_received      = 0;
    memoryZero(parser->handshake_header, sizeof(parser->handshake_header));
}

static bool realityserverTlsParserFail(realityserver_tls_parser_t *parser)
{
    realityserverTlsParserResetHandshake(parser);
    parser->failed = true;
    return false;
}

static bool realityserverTlsParserTargetMessage(const realityserver_tls_parser_t *parser)
{
    return (parser->role == kRealityServerTlsParserClientHello &&
            parser->handshake_type == kTlsHandshakeClientHello) ||
           (parser->role == kRealityServerTlsParserServerHello &&
            parser->handshake_type == kTlsHandshakeServerHello);
}

static bool realityserverTlsParserCompleteHandshake(realityserver_tls_parser_t *parser,
                                                    realityserver_tls_capture_t *capture)
{
    if (! realityserverTlsParserTargetMessage(parser))
    {
        realityserverTlsParserResetHandshake(parser);
        return true;
    }

    bool ok                  = false;
    bool hello_retry_request = false;
    if (parser->role == kRealityServerTlsParserClientHello)
    {
        ok = realityserverParseClientHello(parser->handshake_body, parser->handshake_length, capture);
    }
    else
    {
        ok = realityserverParseServerHello(
            parser->handshake_body, parser->handshake_length, capture, &hello_retry_request);
    }

    realityserverTlsParserResetHandshake(parser);
    if (! ok)
    {
        return realityserverTlsParserFail(parser);
    }

    if (! hello_retry_request)
    {
        parser->complete = true;
    }
    return true;
}

static bool realityserverTlsParserFeedHandshake(realityserver_tls_parser_t *parser, const uint8_t *data,
                                                size_t len, realityserver_tls_capture_t *capture)
{
    while (len > 0 && ! parser->complete)
    {
        if (parser->handshake_header_length < kTlsHandshakeHeaderSize)
        {
            size_t needed = kTlsHandshakeHeaderSize - parser->handshake_header_length;
            size_t take   = min(needed, len);
            memoryCopy(parser->handshake_header + parser->handshake_header_length, data, take);
            parser->handshake_header_length += (uint8_t) take;
            data += take;
            len -= take;

            if (parser->handshake_header_length < kTlsHandshakeHeaderSize)
            {
                return true;
            }

            parser->handshake_type = parser->handshake_header[0];
            parser->handshake_length = ((uint32_t) parser->handshake_header[1] << 16) |
                                       ((uint32_t) parser->handshake_header[2] << 8) |
                                       (uint32_t) parser->handshake_header[3];
            if (parser->handshake_length == 0 || parser->handshake_length > kTlsMaximumHelloBody)
            {
                return realityserverTlsParserFail(parser);
            }

            if (realityserverTlsParserTargetMessage(parser))
            {
                parser->handshake_body = memoryAllocate(parser->handshake_length);
                if (parser->handshake_body == NULL)
                {
                    return realityserverTlsParserFail(parser);
                }
            }
        }

        size_t needed = parser->handshake_length - parser->handshake_received;
        size_t take   = min(needed, len);
        if (parser->handshake_body != NULL)
        {
            memoryCopy(parser->handshake_body + parser->handshake_received, data, take);
        }
        parser->handshake_received += (uint32_t) take;
        data += take;
        len -= take;

        if (parser->handshake_received == parser->handshake_length &&
            ! realityserverTlsParserCompleteHandshake(parser, capture))
        {
            return false;
        }
    }
    return true;
}

void realityserverTlsParserInitialize(realityserver_tls_parser_t *parser, uint8_t role)
{
    *parser       = (realityserver_tls_parser_t) {0};
    parser->role = role;
}

void realityserverTlsParserDestroy(realityserver_tls_parser_t *parser)
{
    realityserverTlsParserResetHandshake(parser);
    memoryZero(parser, sizeof(*parser));
}

bool realityserverTlsParserFeed(realityserver_tls_parser_t *parser, const uint8_t *data, size_t len,
                                realityserver_tls_capture_t *capture)
{
    if (parser == NULL || capture == NULL || (data == NULL && len != 0) || parser->failed)
    {
        return false;
    }
    if (parser->complete)
    {
        return true;
    }

    while (len > 0)
    {
        if (parser->record_header_length < kTlsRecordHeaderSize)
        {
            size_t needed = kTlsRecordHeaderSize - parser->record_header_length;
            size_t take   = min(needed, len);
            memoryCopy(parser->record_header + parser->record_header_length, data, take);
            parser->record_header_length += (uint8_t) take;
            data += take;
            len -= take;

            if (parser->record_header_length < kTlsRecordHeaderSize)
            {
                return true;
            }

            parser->record_type = parser->record_header[0];
            bool valid_type = parser->record_type == kTlsRecordHandshake ||
                              parser->record_type == kTlsRecordChangeCipherSpec ||
                              parser->record_type == kTlsRecordAlert ||
                              parser->record_type == kTlsRecordApplicationData;
            parser->record_remaining = ((uint32_t) parser->record_header[3] << 8) | parser->record_header[4];

            if (! valid_type || parser->record_header[1] != 0x03 || parser->record_header[2] > 0x04 ||
                parser->record_remaining > kTlsMaximumRecordBody ||
                (parser->record_type != kTlsRecordHandshake &&
                 (parser->handshake_header_length != 0 || parser->handshake_received != 0)))
            {
                return realityserverTlsParserFail(parser);
            }

            if (parser->record_type == kTlsRecordApplicationData && ! parser->complete)
            {
                return realityserverTlsParserFail(parser);
            }

            if (parser->record_remaining == 0)
            {
                parser->record_header_length = 0;
                continue;
            }
        }

        size_t take = min((size_t) parser->record_remaining, len);
        if (parser->record_type == kTlsRecordHandshake &&
            ! realityserverTlsParserFeedHandshake(parser, data, take, capture))
        {
            return false;
        }

        data += take;
        len -= take;
        parser->record_remaining -= (uint32_t) take;
        if (parser->record_remaining == 0)
        {
            parser->record_header_length = 0;
            parser->record_type          = 0;
            memoryZero(parser->record_header, sizeof(parser->record_header));
        }

        if (parser->complete)
        {
            return true;
        }
    }
    return true;
}
