#include "tls_client_hello.h"

enum
{
    kTlsRecordHeaderLength      = 5,
    kTlsHandshakeHeaderLength   = 4,
    kTlsClientHelloFixedLength  = 34,
    kTlsExtensionServerName     = 0x0000,
    kTlsExtensionPreSharedKey   = 0x0029,
    kTlsExtensionEncryptedHello = 0xFE0D,
};

static bool rangeContains(size_t offset, size_t length, size_t end)
{
    return offset <= end && length <= end - offset;
}

static void tlsclienthelloInitializeView(tls_client_hello_view_t *view)
{
    memoryZero(view, sizeof(*view));
    view->record_length_field_offset    = UINT32_MAX;
    view->handshake_length_field_offset = UINT32_MAX;
}

static tls_client_hello_result_t tlsclienthelloParseBodyAt(const uint8_t *body, size_t body_length,
                                                           uint32_t body_offset, tls_client_hello_view_t *view)
{
    if (body == NULL || body_length < kTlsClientHelloFixedLength || body_length > UINT32_MAX)
    {
        return kTlsClientHelloMalformed;
    }

    size_t cursor = kTlsClientHelloFixedLength;
    if (! rangeContains(cursor, 1U, body_length))
    {
        return kTlsClientHelloMalformed;
    }

    uint8_t session_id_length = body[cursor++];
    if (! rangeContains(cursor, (size_t) session_id_length + 2U, body_length))
    {
        return kTlsClientHelloMalformed;
    }
    cursor += session_id_length;

    uint16_t cipher_suites_length = GET_BE16(body + cursor);
    cursor += 2U;
    if (! rangeContains(cursor, (size_t) cipher_suites_length + 1U, body_length))
    {
        return kTlsClientHelloMalformed;
    }
    cursor += cipher_suites_length;

    uint8_t compression_methods_length = body[cursor++];
    if (! rangeContains(cursor, compression_methods_length, body_length))
    {
        return kTlsClientHelloMalformed;
    }
    cursor += compression_methods_length;

    if (cursor == body_length)
    {
        return kTlsClientHelloNoSni;
    }
    if (! rangeContains(cursor, 2U, body_length))
    {
        return kTlsClientHelloMalformed;
    }

    size_t   extensions_length_offset = cursor;
    uint16_t extensions_length        = GET_BE16(body + cursor);
    cursor += 2U;
    if (! rangeContains(cursor, extensions_length, body_length) || cursor + extensions_length != body_length)
    {
        return kTlsClientHelloMalformed;
    }

    size_t extensions_offset             = cursor;
    size_t extensions_end                = cursor + extensions_length;
    view->extensions_length_field_offset = body_offset + (uint32_t) extensions_length_offset;
    view->extensions_offset              = body_offset + (uint32_t) extensions_offset;
    view->extensions_length              = extensions_length;

    uint16_t extension_index = 0;
    while (cursor < extensions_end)
    {
        if (! rangeContains(cursor, 4U, extensions_end))
        {
            return kTlsClientHelloMalformed;
        }

        size_t   extension_offset = cursor;
        uint16_t extension_type   = GET_BE16(body + cursor);
        uint16_t extension_length = GET_BE16(body + cursor + 2U);
        cursor += 4U;
        if (! rangeContains(cursor, extension_length, extensions_end))
        {
            return kTlsClientHelloMalformed;
        }

        size_t extension_data_offset = cursor;
        size_t extension_end         = cursor + extension_length;

        if (extension_type == kTlsExtensionServerName && ! view->has_sni)
        {
            if (extension_length < 2U)
            {
                return kTlsClientHelloMalformed;
            }

            uint16_t server_name_list_length = GET_BE16(body + cursor);
            size_t   names_cursor            = cursor + 2U;
            size_t   names_end               = names_cursor + server_name_list_length;
            if (names_end != extension_end)
            {
                return kTlsClientHelloMalformed;
            }

            while (names_cursor < names_end)
            {
                if (! rangeContains(names_cursor, 3U, names_end))
                {
                    return kTlsClientHelloMalformed;
                }

                uint8_t  name_type          = body[names_cursor];
                size_t   name_length_offset = names_cursor + 1U;
                uint16_t name_length        = GET_BE16(body + name_length_offset);
                size_t   name_offset        = names_cursor + 3U;
                if (! rangeContains(name_offset, name_length, names_end))
                {
                    return kTlsClientHelloMalformed;
                }

                if (name_type == 0x00U && ! view->has_sni)
                {
                    view->sni_extension_offset                 = body_offset + (uint32_t) extension_offset;
                    view->sni_extension_length_field_offset    = body_offset + (uint32_t) extension_offset + 2U;
                    view->server_name_list_length_field_offset = body_offset + (uint32_t) extension_data_offset;
                    view->sni_name_length_field_offset         = body_offset + (uint32_t) name_length_offset;
                    view->sni_name_offset                      = body_offset + (uint32_t) name_offset;
                    view->sni_extension_length                 = extension_length;
                    view->server_name_list_length              = server_name_list_length;
                    view->sni_name_length                      = name_length;
                    view->sni_extension_index                  = extension_index;
                    view->has_sni                              = true;
                }

                names_cursor = name_offset + name_length;
            }
        }
        else if (extension_type == kTlsExtensionPreSharedKey && ! view->has_psk)
        {
            view->psk_extension_offset = body_offset + (uint32_t) extension_offset;
            view->psk_extension_length = extension_length;
            view->psk_extension_index  = extension_index;
            view->has_psk              = true;
        }
        else if (extension_type == kTlsExtensionEncryptedHello && ! view->has_ech)
        {
            view->ech_extension_offset      = body_offset + (uint32_t) extension_offset;
            view->ech_extension_data_offset = body_offset + (uint32_t) extension_data_offset;
            view->ech_extension_length      = extension_length;
            view->ech_extension_index       = extension_index;
            view->has_ech                   = true;
        }

        cursor = extension_end;
        ++extension_index;
    }

    view->ech_before_sni = view->has_ech && view->has_sni && view->ech_extension_index < view->sni_extension_index;
    return view->has_sni ? kTlsClientHelloFound : kTlsClientHelloNoSni;
}

tls_client_hello_result_t tlsclienthelloParseHandshakeBody(const uint8_t *body, size_t body_length,
                                                           tls_client_hello_view_t *view)
{
    tls_client_hello_view_t parsed;
    tlsclienthelloInitializeView(&parsed);
    parsed.handshake_body_length = body_length <= UINT32_MAX ? (uint32_t) body_length : 0;

    tls_client_hello_result_t result = tlsclienthelloParseBodyAt(body, body_length, 0, &parsed);
    if (view != NULL)
    {
        *view = parsed;
    }
    return result;
}

static tls_client_hello_result_t tlsclienthelloParseHandshakeAt(const uint8_t *handshake, size_t available_length,
                                                                uint32_t                 handshake_offset,
                                                                tls_client_hello_view_t *view)
{
    if (available_length == 0)
    {
        return kTlsClientHelloNeedMore;
    }
    if (handshake[0] != 0x01U)
    {
        return kTlsClientHelloNotClientHello;
    }
    if (available_length < kTlsHandshakeHeaderLength)
    {
        return kTlsClientHelloNeedMore;
    }

    uint32_t body_length = GET_BE24(handshake + 1U);
    if (available_length < kTlsHandshakeHeaderLength + (size_t) body_length)
    {
        return kTlsClientHelloNeedMore;
    }

    view->handshake_offset              = handshake_offset;
    view->handshake_total_length        = kTlsHandshakeHeaderLength + body_length;
    view->handshake_body_offset         = handshake_offset + kTlsHandshakeHeaderLength;
    view->handshake_body_length         = body_length;
    view->handshake_length_field_offset = handshake_offset + 1U;
    return tlsclienthelloParseBodyAt(
        handshake + kTlsHandshakeHeaderLength, body_length, view->handshake_body_offset, view);
}

tls_client_hello_result_t tlsclienthelloParseHandshake(const uint8_t *handshake, size_t available_length,
                                                       tls_client_hello_view_t *view)
{
    tls_client_hello_view_t parsed;
    tlsclienthelloInitializeView(&parsed);

    tls_client_hello_result_t result = handshake == NULL
                                           ? kTlsClientHelloNeedMore
                                           : tlsclienthelloParseHandshakeAt(handshake, available_length, 0, &parsed);
    if (view != NULL)
    {
        *view = parsed;
    }
    return result;
}

tls_client_hello_result_t tlsclienthelloParseRecord(const uint8_t *record, size_t available_length,
                                                    tls_client_hello_view_t *view)
{
    tls_client_hello_view_t parsed;
    tlsclienthelloInitializeView(&parsed);

    tls_client_hello_result_t result = kTlsClientHelloNeedMore;
    if (record == NULL || available_length == 0)
    {
        goto done;
    }
    if (record[0] != 0x16U)
    {
        result = kTlsClientHelloNotClientHello;
        goto done;
    }
    if ((available_length >= 2U && record[1] != 0x03U) || (available_length >= 3U && record[2] > 0x03U))
    {
        result = kTlsClientHelloNotClientHello;
        goto done;
    }
    if (available_length < kTlsRecordHeaderLength)
    {
        goto done;
    }

    uint16_t record_body_length = GET_BE16(record + 3U);
    if (record_body_length < kTlsHandshakeHeaderLength)
    {
        result = kTlsClientHelloMalformed;
        goto done;
    }

    uint32_t record_total_length = kTlsRecordHeaderLength + (uint32_t) record_body_length;
    if (available_length < record_total_length)
    {
        goto done;
    }

    parsed.record_total_length        = record_total_length;
    parsed.record_body_length         = record_body_length;
    parsed.record_length_field_offset = 3U;
    result                            = tlsclienthelloParseHandshakeAt(
        record + kTlsRecordHeaderLength, record_body_length, kTlsRecordHeaderLength, &parsed);
    if (result == kTlsClientHelloNeedMore)
    {
        result = kTlsClientHelloMalformed;
    }

done:
    if (view != NULL)
    {
        *view = parsed;
    }
    return result;
}
