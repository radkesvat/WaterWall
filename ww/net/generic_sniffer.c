#include "generic_sniffer.h"

#include "tls_client_hello.h"

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

static int classifyHttpMethodEx(const uint8_t *p, uint32_t n, bool include_http2_preface)
{
    static const char *const http1_methods[] = {
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ", NULL};

    bool any_prefix = false;

    for (int i = 0; http1_methods[i] != NULL; ++i)
    {
        const char *m    = http1_methods[i];
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

    if (include_http2_preface)
    {
        static const char h2_preface_method[] = "PRI ";
        uint32_t          mlen                = (uint32_t) stringLength(h2_preface_method);
        uint32_t          cmp                 = n < mlen ? n : mlen;

        if (memoryCompare(p, h2_preface_method, cmp) == 0)
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

static int classifyHttpMethod(const uint8_t *p, uint32_t n)
{
    return classifyHttpMethodEx(p, n, true);
}

static int classifyHttp1Method(const uint8_t *p, uint32_t n)
{
    return classifyHttpMethodEx(p, n, false);
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

void genericsnifferStripHostPortAndDot(const uint8_t **host, uint32_t *host_len)
{
    if (host == NULL || *host == NULL || host_len == NULL)
    {
        return;
    }

    while (*host_len > 0 &&
           ((*host)[*host_len - 1U] == ' ' || (*host)[*host_len - 1U] == '\t' || (*host)[*host_len - 1U] == '\r'))
    {
        *host_len -= 1U;
    }

    if (*host_len > 0 && (*host)[0] == '[')
    {
        return;
    }

    int  colon_index     = -1;
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

static generic_sniffer_result_t findHttpHeader(const uint8_t *p, uint32_t n, const char *name, const uint8_t **value,
                                               uint32_t *value_len)
{
    uint32_t header_end = 0;
    if (! findHeaderEnd(p, n, &header_end))
    {
        return n < (uint32_t) kGenericSnifferMaxWindowBytes ? kGenericSnifferNeedMore : kGenericSnifferMissing;
    }

    uint32_t request_line_end = 0;
    if (! findLineFeed(p, 0, header_end, &request_line_end))
    {
        return kGenericSnifferMissing;
    }

    uint32_t line_start = request_line_end + 1U;
    while (line_start < header_end)
    {
        uint32_t line_end = header_end;
        discard  findLineFeed(p, line_start, header_end, &line_end);

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

        if (colon < content_end && headerNameEquals(p + line_start, name_end - line_start, name))
        {
            uint32_t value_start = colon + 1U;
            while (value_start < content_end && (p[value_start] == ' ' || p[value_start] == '\t'))
            {
                ++value_start;
            }

            if (value != NULL && value_len != NULL)
            {
                *value     = p + value_start;
                *value_len = content_end - value_start;
            }
            return kGenericSnifferFound;
        }

        line_start = line_end + 1U;
    }

    return kGenericSnifferMissing;
}

static generic_sniffer_result_t findHttpHost(const uint8_t *p, uint32_t n, const uint8_t **host, uint32_t *host_len)
{
    const uint8_t           *value     = NULL;
    uint32_t                 value_len = 0;
    generic_sniffer_result_t result    = findHttpHeader(p, n, "host", &value, &value_len);
    if (result != kGenericSnifferFound)
    {
        return result;
    }

    genericsnifferStripHostPortAndDot(&value, &value_len);
    if (value_len == 0)
    {
        return kGenericSnifferMissing;
    }

    *host     = value;
    *host_len = value_len;
    return kGenericSnifferFound;
}

generic_sniffer_result_t genericsnifferSniffHttp1Host(const uint8_t *payload, uint32_t payload_len,
                                                      const uint8_t **host, uint32_t *host_len)
{
    if (payload_len == 0)
    {
        return kGenericSnifferNeedMore;
    }

    int http_method = classifyHttpMethod(payload, payload_len);
    if (http_method < 0 && payload_len < (uint32_t) kGenericSnifferMethodDecideBytes)
    {
        return kGenericSnifferNeedMore;
    }

    if (http_method <= 0)
    {
        return kGenericSnifferMissing;
    }

    return findHttpHost(payload, payload_len, host, host_len);
}

generic_sniffer_result_t genericsnifferSniffHttp1Request(const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len == 0)
    {
        return kGenericSnifferNeedMore;
    }

    int http_method = classifyHttp1Method(payload, payload_len);
    if (http_method < 0 && payload_len < (uint32_t) kGenericSnifferMethodDecideBytes)
    {
        return kGenericSnifferNeedMore;
    }

    return http_method > 0 ? kGenericSnifferFound : kGenericSnifferMissing;
}

generic_sniffer_result_t genericsnifferSniffHttp1UpgradeHeader(const uint8_t *payload, uint32_t payload_len)
{
    if (payload_len == 0)
    {
        return kGenericSnifferNeedMore;
    }

    int http_method = classifyHttpMethod(payload, payload_len);
    if (http_method < 0 && payload_len < (uint32_t) kGenericSnifferMethodDecideBytes)
    {
        return kGenericSnifferNeedMore;
    }

    if (http_method <= 0)
    {
        return kGenericSnifferMissing;
    }

    return findHttpHeader(payload, payload_len, "upgrade", NULL, NULL);
}

generic_sniffer_result_t genericsnifferSniffTlsClientHello(const uint8_t *payload, uint32_t payload_len)
{
    tls_client_hello_result_t result = tlsclienthelloParseRecord(payload, payload_len, NULL);
    if (result == kTlsClientHelloNeedMore)
    {
        return payload_len < (uint32_t) kGenericSnifferMaxWindowBytes ? kGenericSnifferNeedMore
                                                                      : kGenericSnifferMissing;
    }

    return result == kTlsClientHelloFound || result == kTlsClientHelloNoSni ? kGenericSnifferFound
                                                                            : kGenericSnifferMissing;
}

generic_sniffer_result_t genericsnifferSniffTlsClientHelloSni(const uint8_t *payload, uint32_t payload_len,
                                                              const uint8_t **host, uint32_t *host_len)
{
    tls_client_hello_view_t   hello  = {0};
    tls_client_hello_result_t result = tlsclienthelloParseRecord(payload, payload_len, &hello);
    if (result == kTlsClientHelloNeedMore)
    {
        return payload_len < (uint32_t) kGenericSnifferMaxWindowBytes ? kGenericSnifferNeedMore
                                                                      : kGenericSnifferMissing;
    }
    if (result != kTlsClientHelloFound)
    {
        return kGenericSnifferMissing;
    }

    const uint8_t *value     = payload + hello.sni_name_offset;
    uint32_t       value_len = hello.sni_name_length;
    genericsnifferStripHostPortAndDot(&value, &value_len);
    if (value_len == 0)
    {
        return kGenericSnifferMissing;
    }

    *host     = value;
    *host_len = value_len;
    return kGenericSnifferFound;
}

generic_sniffer_result_t genericsnifferSniffBittorrentHandshake(const uint8_t *payload, uint32_t payload_len)
{
    static const uint8_t bittorrent_prefix[20] = {
        19, 'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't', ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
    };

    if (payload_len == 0)
    {
        return kGenericSnifferNeedMore;
    }

    uint32_t compare_len =
        payload_len < (uint32_t) sizeof(bittorrent_prefix) ? payload_len : (uint32_t) sizeof(bittorrent_prefix);
    if (memoryCompare(payload, bittorrent_prefix, compare_len) != 0)
    {
        return kGenericSnifferMissing;
    }

    return payload_len < (uint32_t) sizeof(bittorrent_prefix) ? kGenericSnifferNeedMore : kGenericSnifferFound;
}
