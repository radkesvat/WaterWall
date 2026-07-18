#include "structure.h"

enum
{
    kTlsHandshakeHeaderSize    = 4,
    kTlsHandshakeClientHello   = 0x01,
    kTlsHandshakeServerHello   = 0x02,
    kTlsExtensionSupportedVersions = 0x002b,
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

enum realityserver_tls_record_prefix_e
realityserverClassifyTlsRecordPrefix(const uint8_t *prefix, size_t available_length)
{
    size_t prefix_length = min(available_length, (size_t) kRealityServerTlsHeaderSize);
    if (prefix_length == 0)
    {
        return kRealityServerTlsRecordPrefixNeedMore;
    }
    assert(prefix != NULL);

    if (prefix[0] != kRealityServerTlsChangeCipherSpec &&
        prefix[0] != kRealityServerTlsAlert && prefix[0] != kRealityServerTlsHandshake &&
        prefix[0] != kRealityServerTlsApplicationData)
    {
        return kRealityServerTlsRecordPrefixInvalid;
    }
    if (prefix_length == 1)
    {
        return kRealityServerTlsRecordPrefixNeedMore;
    }
    if (prefix[1] != kRealityServerTlsVersionMajor)
    {
        return kRealityServerTlsRecordPrefixInvalid;
    }
    if (prefix_length == 2)
    {
        return kRealityServerTlsRecordPrefixNeedMore;
    }
    if (prefix[2] > 0x04)
    {
        return kRealityServerTlsRecordPrefixInvalid;
    }
    if (prefix_length < kRealityServerTlsHeaderSize)
    {
        return kRealityServerTlsRecordPrefixNeedMore;
    }

    uint32_t body_length = ((uint32_t) prefix[3] << 8) | prefix[4];
    return body_length <= kRealityServerMaxTlsRecordBody
               ? kRealityServerTlsRecordPrefixComplete
               : kRealityServerTlsRecordPrefixInvalid;
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

    uint16_t parsed_legacy_version = realityserverReadBe16(legacy_version);
    if (parsed_legacy_version < 0x0301 || parsed_legacy_version > 0x0303)
    {
        return false;
    }
    capture->client_legacy_version = parsed_legacy_version;
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
        if (parser->record_header_length < kRealityServerTlsHeaderSize)
        {
            size_t needed = kRealityServerTlsHeaderSize - parser->record_header_length;
            size_t take   = min(needed, len);
            memoryCopy(parser->record_header + parser->record_header_length, data, take);
            parser->record_header_length += (uint8_t) take;
            data += take;
            len -= take;

            enum realityserver_tls_record_prefix_e prefix_result =
                realityserverClassifyTlsRecordPrefix(parser->record_header,
                                                     parser->record_header_length);
            if (prefix_result == kRealityServerTlsRecordPrefixInvalid)
            {
                return realityserverTlsParserFail(parser);
            }
            if (prefix_result == kRealityServerTlsRecordPrefixNeedMore)
            {
                return true;
            }

            parser->record_type = parser->record_header[0];
            parser->record_remaining = ((uint32_t) parser->record_header[3] << 8) | parser->record_header[4];

            if ((parser->record_type != kRealityServerTlsHandshake &&
                 (parser->handshake_header_length != 0 || parser->handshake_received != 0)))
            {
                return realityserverTlsParserFail(parser);
            }

            if (parser->record_type == kRealityServerTlsApplicationData && ! parser->complete)
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
        if (parser->record_type == kRealityServerTlsHandshake &&
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

static bool realityserverTls12RecordTrackerFail(realityserver_tls12_record_tracker_t *tracker)
{
    tracker->failed = true;
    return false;
}

static bool realityserverTls12ProtectedLengthIsValid(const realityserver_tls12_record_tracker_t *tracker)
{
    uint32_t body_len = tracker->record_body_len;
    switch (tracker->profile.profile_id)
    {
        case kRealityV2RecordProfileTls12ChaCha:
            return body_len >= kRealityV2TagSize && body_len <= kRealityV2MaxTlsRecordBody;
        case kRealityV2RecordProfileTls12Gcm:
            return body_len >= kRealityV2Tls12GcmPrefixSize + kRealityV2TagSize &&
                   body_len <= kRealityV2MaxTlsRecordBody;
        case kRealityV2RecordProfileTls12Cbc:
        {
            reality_v2_record_layout_t minimum;
            return realityV2CalculateRecordLayout(&tracker->profile, 0, &minimum) &&
                   body_len >= minimum.wire_body_len && body_len <= kRealityV2MaxTlsRecordBody &&
                   ((body_len - kRealityV2Tls12CbcPrefixSize) % tracker->profile.block_size) == 0;
        }
        default:
            return false;
    }
}

void realityserverTls12RecordTrackerInitialize(realityserver_tls12_record_tracker_t *tracker)
{
    *tracker = (realityserver_tls12_record_tracker_t) {
        .sequence_pattern = true,
        .counter_pattern  = true,
    };
}

void realityserverTlsRecordBoundaryTrackerInitialize(realityserver_tls_record_boundary_tracker_t *tracker)
{
    assert(tracker != NULL);
    *tracker = (realityserver_tls_record_boundary_tracker_t) {0};
}

void realityserverTlsRecordBoundaryTrackerDestroy(realityserver_tls_record_boundary_tracker_t *tracker)
{
    if (tracker != NULL)
    {
        memoryZero(tracker, sizeof(*tracker));
    }
}

bool realityserverTlsRecordBoundaryTrackerIsAtBoundary(
    const realityserver_tls_record_boundary_tracker_t *tracker)
{
    return tracker != NULL && ! tracker->failed && tracker->record_header_length == 0 &&
           tracker->record_remaining == 0;
}

static bool realityserverTlsRecordBoundaryTrackerFail(
    realityserver_tls_record_boundary_tracker_t *tracker, size_t offset, size_t *consumed)
{
    tracker->failed = true;
    if (consumed != NULL)
    {
        *consumed = offset;
    }
    return false;
}

bool realityserverTlsRecordBoundaryTrackerFeed(realityserver_tls_record_boundary_tracker_t *tracker,
                                               const uint8_t *data, size_t len,
                                               bool stop_at_boundary, size_t *consumed)
{
    if (tracker == NULL || consumed == NULL || (data == NULL && len != 0) || tracker->failed)
    {
        return false;
    }

    size_t offset = 0;
    *consumed     = 0;
    while (offset < len)
    {
        if (tracker->record_header_length < kRealityV2TlsRecordHeaderSize)
        {
            size_t needed = kRealityV2TlsRecordHeaderSize - tracker->record_header_length;
            size_t take   = min(needed, len - offset);
            memoryCopy(tracker->record_header + tracker->record_header_length, data + offset, take);
            tracker->record_header_length += (uint8_t) take;
            offset += take;

            if (tracker->record_header_length < kRealityV2TlsRecordHeaderSize)
            {
                break;
            }

            uint8_t type = tracker->record_header[0];
            bool valid_type = type == kRealityServerTlsChangeCipherSpec ||
                              type == kRealityServerTlsAlert ||
                              type == kRealityServerTlsHandshake ||
                              type == kRealityServerTlsApplicationData;
            uint32_t body_len = ((uint32_t) tracker->record_header[3] << 8) |
                                tracker->record_header[4];
            if (! valid_type || tracker->record_header[1] != kRealityServerTlsVersionMajor ||
                tracker->record_header[2] != kRealityServerTlsVersionMinor ||
                body_len > kRealityV2MaxTlsRecordBody)
            {
                return realityserverTlsRecordBoundaryTrackerFail(tracker, offset, consumed);
            }
            tracker->record_remaining = body_len;
        }

        size_t take = min((size_t) tracker->record_remaining, len - offset);
        tracker->record_remaining -= (uint32_t) take;
        offset += take;
        if (tracker->record_remaining != 0)
        {
            break;
        }

        tracker->record_header_length = 0;
        memoryZero(tracker->record_header, sizeof(tracker->record_header));
        if (stop_at_boundary)
        {
            break;
        }
    }

    *consumed = offset;
    return true;
}

bool realityserverTls12RecordTrackerSetProfile(realityserver_tls12_record_tracker_t *tracker,
                                               const reality_v2_record_profile_t *profile)
{
    if (tracker == NULL || tracker->failed || tracker->frozen || tracker->record_header_length != 0 ||
        tracker->record_remaining != 0 || ! realityV2RecordProfileIsValid(profile) ||
        profile->profile_id == kRealityV2RecordProfileTls13Aead)
    {
        return false;
    }

    tracker->profile = *profile;
    return true;
}

bool realityserverTls12RecordTrackerFeed(realityserver_tls12_record_tracker_t *tracker,
                                         const uint8_t *data, size_t len)
{
    if (tracker == NULL || (data == NULL && len != 0) || tracker->failed ||
        ! realityV2RecordProfileIsValid(&tracker->profile))
    {
        return false;
    }
    if (tracker->frozen)
    {
        return true;
    }

    while (len > 0)
    {
        if (tracker->record_header_length < kRealityServerTlsHeaderSize)
        {
            if (tracker->record_header_length == 0)
            {
                tracker->last_record_was_protected = false;
            }

            size_t needed = kRealityServerTlsHeaderSize - tracker->record_header_length;
            size_t take   = min(needed, len);
            memoryCopy(tracker->record_header + tracker->record_header_length, data, take);
            tracker->record_header_length += (uint8_t) take;
            data += take;
            len -= take;

            if (tracker->record_header_length < kRealityServerTlsHeaderSize)
            {
                return true;
            }

            tracker->record_type = tracker->record_header[0];
            bool valid_type = tracker->record_type == kRealityServerTlsHandshake ||
                              tracker->record_type == kRealityServerTlsChangeCipherSpec ||
                              tracker->record_type == kRealityServerTlsAlert ||
                              tracker->record_type == kRealityServerTlsApplicationData;
            tracker->record_body_len = ((uint32_t) tracker->record_header[3] << 8) |
                                       tracker->record_header[4];
            tracker->record_remaining         = tracker->record_body_len;
            tracker->current_record_protected = tracker->protected_epoch;
            tracker->explicit_nonce_length    = 0;
            tracker->ccs_value                = 0;

            if (! valid_type || tracker->record_header[1] != 0x03 || tracker->record_header[2] > 0x03 ||
                tracker->record_body_len > kRealityV2MaxTlsRecordBody ||
                (tracker->current_record_protected && ! realityserverTls12ProtectedLengthIsValid(tracker)) ||
                (! tracker->current_record_protected &&
                 tracker->record_type == kRealityServerTlsChangeCipherSpec &&
                 tracker->record_body_len != 1))
            {
                return realityserverTls12RecordTrackerFail(tracker);
            }

            if (tracker->current_record_protected)
            {
                tracker->last_record_sequence = tracker->next_sequence;
            }
        }

        uint32_t body_offset = tracker->record_body_len - tracker->record_remaining;
        size_t   take        = min((size_t) tracker->record_remaining, len);
        if (tracker->current_record_protected &&
            tracker->profile.profile_id == kRealityV2RecordProfileTls12Gcm && body_offset < 8)
        {
            size_t nonce_take = min(take, (size_t) 8 - body_offset);
            memoryCopy(tracker->explicit_nonce + body_offset, data, nonce_take);
            tracker->explicit_nonce_length += (uint8_t) nonce_take;
        }
        else if (! tracker->current_record_protected &&
                 tracker->record_type == kRealityServerTlsChangeCipherSpec && body_offset == 0 && take > 0)
        {
            tracker->ccs_value = data[0];
        }

        data += take;
        len -= take;
        tracker->record_remaining -= (uint32_t) take;
        if (tracker->record_remaining != 0)
        {
            continue;
        }

        if (tracker->current_record_protected)
        {
            if (tracker->next_sequence == UINT64_MAX)
            {
                return realityserverTls12RecordTrackerFail(tracker);
            }

            if (tracker->profile.profile_id == kRealityV2RecordProfileTls12Gcm)
            {
                if (tracker->explicit_nonce_length != 8)
                {
                    return realityserverTls12RecordTrackerFail(tracker);
                }
                uint64_t explicit_nonce = realityV2ReadBe64(tracker->explicit_nonce);
                if (explicit_nonce != tracker->next_sequence)
                {
                    tracker->sequence_pattern = false;
                }
                if (tracker->explicit_nonce_sample_count > 0 &&
                    (tracker->last_explicit_nonce == UINT64_MAX ||
                     explicit_nonce != tracker->last_explicit_nonce + 1U))
                {
                    tracker->counter_pattern = false;
                }
                tracker->last_explicit_nonce = explicit_nonce;
                ++tracker->explicit_nonce_sample_count;
            }

            ++tracker->next_sequence;
            tracker->saw_protected_record      = true;
            tracker->last_record_was_protected = true;
        }
        else if (tracker->record_type == kRealityServerTlsChangeCipherSpec)
        {
            if (tracker->ccs_value != 1)
            {
                return realityserverTls12RecordTrackerFail(tracker);
            }
            tracker->protected_epoch = true;
            tracker->next_sequence   = 0;
        }

        tracker->record_header_length     = 0;
        tracker->record_type              = 0;
        tracker->record_body_len          = 0;
        tracker->current_record_protected = false;
        memoryZero(tracker->record_header, sizeof(tracker->record_header));
        memoryZero(tracker->explicit_nonce, sizeof(tracker->explicit_nonce));
    }
    return true;
}

void realityserverTls12RecordTrackerFreeze(realityserver_tls12_record_tracker_t *tracker)
{
    if (tracker != NULL)
    {
        tracker->frozen = true;
    }
}

void realityserverTls12RecordTrackerDestroy(realityserver_tls12_record_tracker_t *tracker)
{
    if (tracker != NULL)
    {
        memoryZero(tracker, sizeof(*tracker));
    }
}

bool realityserverResolveGcmNoncePolicy(uint8_t configured_policy,
                                        const realityserver_tls12_record_tracker_t *server_tracker,
                                        uint8_t *resolved_policy, uint64_t *counter_next)
{
    if (server_tracker == NULL || resolved_policy == NULL || counter_next == NULL ||
        configured_policy < kRealityServerGcmNoncePolicyAuto ||
        configured_policy > kRealityServerGcmNoncePolicyRandom)
    {
        return false;
    }

    uint8_t policy = configured_policy;
    if (policy == kRealityServerGcmNoncePolicyAuto)
    {
        if (server_tracker->explicit_nonce_sample_count >= 1 && server_tracker->sequence_pattern)
        {
            policy = kRealityServerGcmNoncePolicySequence;
        }
        else if (server_tracker->explicit_nonce_sample_count >= 2 && server_tracker->counter_pattern)
        {
            policy = kRealityServerGcmNoncePolicyCounter;
        }
        else
        {
            policy = kRealityServerGcmNoncePolicyRandom;
        }
    }

    uint64_t next = 0;
    if (policy == kRealityServerGcmNoncePolicyCounter)
    {
        if (server_tracker->explicit_nonce_sample_count == 0 || server_tracker->last_explicit_nonce == UINT64_MAX)
        {
            return false;
        }
        next = server_tracker->last_explicit_nonce + 1U;
    }

    *resolved_policy = policy;
    *counter_next     = next;
    return true;
}
