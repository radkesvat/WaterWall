#include "protocol_sniff.h"

static bool headerNameEquals(const uint8_t *p, uint32_t n, const char *name)
{
    for (uint32_t i = 0; i < n; ++i)
    {
        if (name[i] == '\0' || asciiLower(p[i]) != (uint8_t) name[i])
        {
            return false;
        }
    }
    return name[n] == '\0';
}

static int classifyHttpMethod(const uint8_t *p, uint32_t n)
{
    static const char *const methods[] = {"GET ",     "POST ",  "PUT ",     "HEAD ", "DELETE ",
                                           "OPTIONS ", "PATCH ", "TRACE ",   "CONNECT ",
                                           "PRI ", /* HTTP/2 connection preface: "PRI * HTTP/2.0" */
                                           NULL};

    bool any_prefix = false;

    for (int i = 0; methods[i] != NULL; ++i)
    {
        const char *m    = methods[i];
        uint32_t    mlen = (uint32_t) stringLength(m);
        uint32_t    cmp  = n < mlen ? n : mlen;

        if (memoryCompare(p, m, cmp) == 0)
        {
            if (n >= mlen)
            {
                return 1;
            }
            any_prefix = true;
        }
    }

    return any_prefix ? -1 : 0;
}

static bool findLineFeed(const uint8_t *p, uint32_t start, uint32_t end, uint32_t *lf)
{
    for (uint32_t i = start; i < end; ++i)
    {
        if (p[i] == '\n')
        {
            *lf = i;
            return true;
        }
    }
    return false;
}

static bool findHeaderEnd(const uint8_t *p, uint32_t n, uint32_t *header_end)
{
    for (uint32_t i = 0; i + 3U < n; ++i)
    {
        if (p[i] == '\r' && p[i + 1U] == '\n' && p[i + 2U] == '\r' && p[i + 3U] == '\n')
        {
            *header_end = i;
            return true;
        }
    }

    for (uint32_t i = 0; i + 1U < n; ++i)
    {
        if (p[i] == '\n' && p[i + 1U] == '\n')
        {
            *header_end = i;
            return true;
        }
    }

    return false;
}

static void stripHostPortAndDot(const uint8_t **host, uint32_t *host_len)
{
    while (*host_len > 0 && ((*host)[*host_len - 1U] == ' ' || (*host)[*host_len - 1U] == '\t' ||
                             (*host)[*host_len - 1U] == '\r'))
    {
        *host_len -= 1U;
    }

    if (*host_len > 0 && (*host)[0] == '[')
    {
        return;
    }

    int  colon_index    = -1;
    bool multiple_colons = false;

    for (uint32_t i = 0; i < *host_len; ++i)
    {
        if ((*host)[i] == ':')
        {
            if (colon_index >= 0)
            {
                multiple_colons = true;
                break;
            }
            colon_index = (int) i;
        }
    }

    if (colon_index > 0 && ! multiple_colons && (uint32_t) colon_index + 1U < *host_len)
    {
        bool port_is_numeric = true;
        for (uint32_t i = (uint32_t) colon_index + 1U; i < *host_len; ++i)
        {
            if ((*host)[i] < '0' || (*host)[i] > '9')
            {
                port_is_numeric = false;
                break;
            }
        }

        if (port_is_numeric)
        {
            *host_len = (uint32_t) colon_index;
        }
    }

    while (*host_len > 0 && (*host)[*host_len - 1U] == '.')
    {
        *host_len -= 1U;
    }
}

static protocol_sniff_result_t findHttpHost(const uint8_t *p, uint32_t n, const uint8_t **host,
                                            uint32_t *host_len)
{
    uint32_t header_end = 0;
    if (! findHeaderEnd(p, n, &header_end))
    {
        return n < (uint32_t) kProtocolSniffMaxWindowBytes ? kProtocolSniffNeedMore : kProtocolSniffMissing;
    }

    uint32_t request_line_end = 0;
    if (! findLineFeed(p, 0, header_end, &request_line_end))
    {
        return kProtocolSniffMissing;
    }

    uint32_t line_start = request_line_end + 1U;
    while (line_start < header_end)
    {
        uint32_t line_end = header_end;
        discard findLineFeed(p, line_start, header_end, &line_end);

        uint32_t content_end = line_end;
        if (content_end > line_start && p[content_end - 1U] == '\r')
        {
            content_end -= 1U;
        }

        uint32_t colon = line_start;
        while (colon < content_end && p[colon] != ':')
        {
            ++colon;
        }

        uint32_t name_end = colon;
        while (name_end > line_start && (p[name_end - 1U] == ' ' || p[name_end - 1U] == '\t'))
        {
            name_end -= 1U;
        }

        if (colon < content_end && headerNameEquals(p + line_start, name_end - line_start, "host"))
        {
            uint32_t value_start = colon + 1U;
            while (value_start < content_end && (p[value_start] == ' ' || p[value_start] == '\t'))
            {
                ++value_start;
            }

            const uint8_t *value     = p + value_start;
            uint32_t       value_len = content_end - value_start;
            stripHostPortAndDot(&value, &value_len);

            if (value_len == 0)
            {
                return kProtocolSniffMissing;
            }

            *host     = value;
            *host_len = value_len;
            return kProtocolSniffFound;
        }

        line_start = line_end + 1U;
    }

    return kProtocolSniffMissing;
}

protocol_sniff_result_t protocolsniffHttpHost(const uint8_t *payload, uint32_t payload_len, const uint8_t **host,
                                              uint32_t *host_len)
{
    if (payload_len == 0)
    {
        return kProtocolSniffNeedMore;
    }

    int http_method = classifyHttpMethod(payload, payload_len);
    if (http_method < 0 && payload_len < (uint32_t) kProtocolSniffMethodDecideBytes)
    {
        return kProtocolSniffNeedMore;
    }

    if (http_method <= 0)
    {
        return kProtocolSniffMissing;
    }

    return findHttpHost(payload, payload_len, host, host_len);
}

static bool remainingAtLeast(const uint8_t *cursor, const uint8_t *end, size_t needed)
{
    return cursor <= end && (size_t) (end - cursor) >= needed;
}

protocol_sniff_result_t protocolsniffTlsClientHelloSni(const uint8_t *payload, uint32_t payload_len,
                                                       const uint8_t **host, uint32_t *host_len)
{
    if (payload_len == 0)
    {
        return kProtocolSniffNeedMore;
    }

    if (payload[0] != 0x16)
    {
        return kProtocolSniffMissing;
    }

    if (payload_len < 5U)
    {
        return kProtocolSniffNeedMore;
    }

    if (payload[1] != 0x03 || payload[2] > 0x03)
    {
        return kProtocolSniffMissing;
    }

    uint16_t tls_record_len = GET_BE16(payload + 3);
    if (tls_record_len < 4U)
    {
        return kProtocolSniffMissing;
    }

    uint32_t tls_record_total_len = (uint32_t) tls_record_len + 5U;
    if (payload_len < tls_record_total_len)
    {
        return payload_len < (uint32_t) kProtocolSniffMaxWindowBytes ? kProtocolSniffNeedMore
                                                                     : kProtocolSniffMissing;
    }

    if (payload[5] != 0x01)
    {
        return kProtocolSniffMissing;
    }

    uint32_t client_hello_len = GET_BE24(payload + 6);
    if (client_hello_len < 34U || client_hello_len + 4U > (uint32_t) tls_record_len)
    {
        return kProtocolSniffMissing;
    }

    const uint8_t *client_hello = payload + 9;
    const uint8_t *cursor       = client_hello + 34;
    const uint8_t *hello_end    = client_hello + client_hello_len;

    if (! remainingAtLeast(cursor, hello_end, 1U))
    {
        return kProtocolSniffMissing;
    }

    uint8_t session_id_len = cursor[0];
    cursor += 1;
    if (! remainingAtLeast(cursor, hello_end, (size_t) session_id_len + 2U))
    {
        return kProtocolSniffMissing;
    }
    cursor += session_id_len;

    uint16_t cipher_suites_len = GET_BE16(cursor);
    cursor += 2;
    if (! remainingAtLeast(cursor, hello_end, (size_t) cipher_suites_len + 1U))
    {
        return kProtocolSniffMissing;
    }
    cursor += cipher_suites_len;

    uint8_t compression_methods_len = cursor[0];
    cursor += 1;
    if (! remainingAtLeast(cursor, hello_end, (size_t) compression_methods_len + 2U))
    {
        return kProtocolSniffMissing;
    }
    cursor += compression_methods_len;

    uint16_t extensions_len = GET_BE16(cursor);
    cursor += 2;
    if (! remainingAtLeast(cursor, hello_end, extensions_len))
    {
        return kProtocolSniffMissing;
    }

    const uint8_t *extensions_end = cursor + extensions_len;
    while (remainingAtLeast(cursor, extensions_end, 4U))
    {
        uint16_t       extension_type = GET_BE16(cursor);
        uint16_t       extension_len  = GET_BE16(cursor + 2);
        const uint8_t *extension_data = cursor + 4;
        if (! remainingAtLeast(extension_data, extensions_end, extension_len))
        {
            return kProtocolSniffMissing;
        }
        const uint8_t *next_extension = extension_data + extension_len;

        if (extension_type == 0x0000)
        {
            if (extension_len < 2U)
            {
                return kProtocolSniffMissing;
            }

            uint16_t       server_name_list_len = GET_BE16(extension_data);
            const uint8_t *server_name_cursor   = extension_data + 2;

            if (server_name_list_len > extension_len - 2U)
            {
                return kProtocolSniffMissing;
            }
            const uint8_t *server_name_list_end = server_name_cursor + server_name_list_len;

            while (remainingAtLeast(server_name_cursor, server_name_list_end, 3U))
            {
                uint8_t        name_type = server_name_cursor[0];
                uint16_t       name_len  = GET_BE16(server_name_cursor + 1);
                const uint8_t *name_data = server_name_cursor + 3;
                if (! remainingAtLeast(name_data, server_name_list_end, name_len))
                {
                    return kProtocolSniffMissing;
                }
                const uint8_t *next_name = name_data + name_len;

                if (name_type == 0x00)
                {
                    const uint8_t *value     = name_data;
                    uint32_t       value_len = name_len;
                    stripHostPortAndDot(&value, &value_len);

                    if (value_len == 0)
                    {
                        return kProtocolSniffMissing;
                    }

                    *host     = value;
                    *host_len = value_len;
                    return kProtocolSniffFound;
                }

                server_name_cursor = next_name;
            }

            return kProtocolSniffMissing;
        }

        cursor = next_extension;
    }

    return kProtocolSniffMissing;
}
