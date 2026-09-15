#include "parser.h"

static int hex(unsigned char c);

static unsigned char lowerAscii(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char) (c + ('a' - 'A')) : c;
}

static bool equal(const char *a, const char *b)
{
    while (*a && *b && lowerAscii((unsigned char) *a) == lowerAscii((unsigned char) *b))
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

static bool token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c != 0 && stringChr("!#$%&'*+-.^_`|~", c) != NULL);
}

static bool number(const char *p, uint64_t *value)
{
    uint64_t n = 0;
    if (! *p)
        return false;
    for (; *p; ++p)
    {
        if (*p < '0' || *p > '9' || n > (UINT64_MAX - (unsigned) (*p - '0')) / 10)
            return false;
        n = n * 10 + (unsigned) (*p - '0');
    }
    *value = n;
    return true;
}

bool hpsAuthority(const char *text, size_t len, bool explicit_port, hps_authority_t *out)
{
    *out = (hps_authority_t) {0};
    if (! len || len >= sizeof(out->wire))
        return false;
    char copy[264];
    memoryCopy(copy, text, len);
    copy[len]  = 0;
    char *host = copy;
    char *port = NULL;
    bool  ipv6 = copy[0] == '[';
    if (ipv6)
    {
        host++;
        char *end = stringChr(host, ']');
        if (! end || (end[1] && end[1] != ':'))
            return false;
        if (end[1])
            port = end + 2;
        *end = 0;
    }
    else
    {
        port = stringChr(host, ':');
        if (port)
            *port++ = 0;
    }
    uint64_t n = 80;
    if ((explicit_port && ! port) || (port && (! number(port, &n) || n == 0 || n > 65535)))
        return false;
    size_t hlen = stringLength(host);
    if (! hlen || hlen > 253)
        return false;
    for (size_t i = 0; i < hlen; ++i)
    {
        unsigned char c = (unsigned char) host[i];
        if (c <= 32 || c >= 127 || stringChr("@%/#?\\[]", c))
            return false;
        host[i] = (char) lowerAscii(c);
    }
    if (ipv6)
    {
        if (! stringChr(host, ':') || ! ipaddr_aton(host, &out->ip) || out->ip.type != IPADDR_TYPE_V6)
            return false;
        out->literal = true;
    }
    else
    {
        bool numeric = true;
        for (size_t i = 0; i < hlen; ++i)
            if ((host[i] < '0' || host[i] > '9') && host[i] != '.')
                numeric = false;
        if (numeric)
        {
            unsigned parts = 0;
            char    *p     = host;
            while (*p)
            {
                char    *start = p;
                unsigned v     = 0;
                while (*p >= '0' && *p <= '9')
                {
                    v = v * 10 + (unsigned) (*p++ - '0');
                    if (v > 255)
                        return false;
                }
                if (p == start || (p - start > 1 && *start == '0') || ++parts > 4)
                    return false;
                if (*p && (*p++ != '.' || ! *p))
                    return false;
            }
            if (parts != 4 || ! ipaddr_aton(host, &out->ip))
                return false;
            out->literal = true;
        }
        else
        {
            /* Reject numeric address spellings accepted by legacy inet_aton. */
            if (ipaddr_aton(host, &out->ip))
                return false;
            size_t label = 0;
            for (size_t i = 0; i < hlen; ++i)
            {
                unsigned char c = (unsigned char) host[i];
                if (c == '.')
                {
                    if (! label || host[i - 1] == '-')
                        return false;
                    label = 0;
                }
                else
                {
                    if (! ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') || (! label && c == '-') ||
                        ++label > 63)
                        return false;
                }
            }
            if (host[hlen - 1] == '-')
                return false;
        }
    }
    memoryCopy(out->host, host, hlen + 1);
    out->port = (uint16_t) n;
    stringNPrintf(out->wire, sizeof(out->wire), ipv6 ? "[%s]:%u" : "%s:%u", host, (unsigned) n);
    return true;
}

bool hpsAuthorityEqual(const hps_authority_t *a, const hps_authority_t *b)
{
    return a->port == b->port && a->literal == b->literal &&
           (a->literal ? ip_addr_cmp(&a->ip, &b->ip) : equal(a->host, b->host));
}

static bool listContains(const char *value, const char *name, bool *valid)
{
    bool        found = false;
    const char *p     = value;
    while (*p)
    {
        while (*p == ' ' || *p == '\t' || *p == ',')
            ++p;
        if (! *p)
            break;
        const char *start = p;
        while (token((unsigned char) *p))
            ++p;
        if (p == start)
        {
            *valid = false;
            return false;
        }
        if ((size_t) (p - start) == stringLength(name))
        {
            bool match = true;
            for (size_t i = 0; i < (size_t) (p - start); ++i)
                match &= lowerAscii((unsigned char) start[i]) == lowerAscii((unsigned char) name[i]);
            found |= match;
        }
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p && *p != ',')
        {
            *valid = false;
            return false;
        }
    }
    return found;
}

static bool field(char *line, hps_field_t *f)
{
    char *p = line;
    while (token((unsigned char) *p))
        ++p;
    if (p == line || *p != ':')
        return false;
    *p++    = 0;
    f->name = line;
    while (*p == ' ' || *p == '\t')
        ++p;
    f->value = p;
    for (; *p; ++p)
        if (((unsigned char) *p < 32 && *p != '\t') || (unsigned char) *p == 127)
            return false;
    while (p > f->value && (p[-1] == ' ' || p[-1] == '\t'))
        *--p = 0;
    return true;
}

unsigned hpsParseHeader(char *block, size_t len, bool response, bool response_to_head, hps_header_t *h)
{
    *h = (hps_header_t) {0};
    if (len < 4 || memoryCompare(block + len - 4, "\r\n\r\n", 4) || memchr(block, 0, len))
        return 400;
    /* Validate every delimiter within the supplied block before mutating it. */
    for (size_t i = 0; i < len; ++i)
    {
        if (block[i] == '\r')
        {
            if (i + 1 == len || block[++i] != '\n')
                return 400;
        }
        else if (block[i] == '\n')
            return 400;
    }
    char *end = memchr(block, '\r', len);
    if (! end || (size_t) (end - block) > kHpsRequestLineLimit)
        return 414;
    *end = 0;
    if (response)
    {
        if (strncmp(block, "HTTP/1.0 ", 9) && strncmp(block, "HTTP/1.1 ", 9))
            return 505;
        h->http10 = block[7] == '0';
        if (stringLength(block) < 13 || block[9] < '1' || block[9] > '5' || block[10] < '0' || block[10] > '9' ||
            block[11] < '0' || block[11] > '9' || block[12] != ' ')
            return 400;
        h->status =
            (unsigned) (block[9] - '0') * 100 + (unsigned) (block[10] - '0') * 10 + (unsigned) (block[11] - '0');
        h->reason = block + 13;
        for (char *p = h->reason; *p; ++p)
            if (((unsigned char) *p < 32 && *p != '\t') || (unsigned char) *p == 127)
                return 400;
        if (h->status == 101)
            return 501;
    }
    else
    {
        h->method = block;
        char *p   = block;
        while (token((unsigned char) *p))
            ++p;
        if (p == block || *p != ' ')
            return 400;
        *p++      = 0;
        h->target = p;
        p         = stringChr(p, ' ');
        if (! p || p == h->target)
            return 400;
        *p++ = 0;
        if (stringCompare(p, "HTTP/1.1") && stringCompare(p, "HTTP/1.0"))
            return 505;
        h->http10  = p[7] == '0';
        h->connect = ! stringCompare(h->method, "CONNECT");
        h->head    = ! stringCompare(h->method, "HEAD");
        h->options = ! stringCompare(h->method, "OPTIONS");
        if (! stringCompare(h->method, "TRACE"))
            return 405;
        for (const char *target = h->target; *target; ++target)
            if ((unsigned char) *target <= 32 || (unsigned char) *target >= 127 || *target == '#' || *target == '\\')
                return 400;
        if (h->connect)
        {
            if (! hpsAuthority(h->target, stringLength(h->target), true, &h->authority))
                return 400;
        }
        else if (h->options && ! stringCompare(h->target, "*"))
            h->local_options = true;
        else
        {
            if (stringLength(h->target) < 7)
                return 400;
            char scheme[8];
            memoryCopy(scheme, h->target, 7);
            scheme[7] = 0;
            if (! equal(scheme, "http://"))
                return 501;
            const char *authority = h->target + 7;
            const char *path      = authority + strcspn(authority, "/?");
            if (! hpsAuthority(authority, (size_t) (path - authority), false, &h->authority))
                return 400;
            h->target = path;
            if (h->options && ! *path)
                h->target = "*";
            for (const char *escaped = h->target; *escaped; ++escaped)
            {
                if (*escaped == '%')
                {
                    if (! escaped[1] || ! escaped[2] || hex((unsigned char) escaped[1]) < 0 ||
                        hex((unsigned char) escaped[2]) < 0)
                        return 400;
                    escaped += 2;
                }
            }
        }
    }
    unsigned hosts = 0, auths = 0, expects = 0;
    char    *line = end + 2;
    while (line < block + len - 2)
    {
        end = memchr(line, '\r', (size_t) (block + len - line));
        if (! end || h->count == kHpsFieldLimit)
            return 431;
        *end           = 0;
        hps_field_t *f = &h->fields[h->count++];
        if (! field(line, f))
            return 400;
        if (equal(f->name, "Content-Length"))
        {
            if (h->has_length || ! number(f->value, &h->length))
                return 400;
            h->has_length = true;
        }
        else if (equal(f->name, "Transfer-Encoding"))
        {
            if (h->chunked || ! equal(f->value, "chunked") || h->http10)
                return 501;
            h->chunked = true;
        }
        else if (equal(f->name, "Connection"))
        {
            bool valid = true;
            h->close |= listContains(f->value, "close", &valid);
            if (listContains(f->value, "upgrade", &valid))
                return 501;
            /* These cannot be erased by a Connection nomination. */
            const char *protected[] = {"host", "content-length", "transfer-encoding", "proxy-authorization", "expect"};
            for (size_t i = 0; i < ARRAY_SIZE(protected); ++i)
                if (listContains(f->value, protected[i], &valid))
                    return 400;
            if (! valid)
                return 400;
        }
        else if (equal(f->name, "Upgrade"))
            return 501;
        else if (! response && equal(f->name, "Host"))
        {
            hps_authority_t ignored;
            if (++hosts > 1 || ! hpsAuthority(f->value, stringLength(f->value), false, &ignored))
                return 400;
        }
        else if (! response && equal(f->name, "Proxy-Authorization"))
        {
            if (++auths > 1)
                return 400;
            h->credentials = f->value;
        }
        else if (! response && equal(f->name, "Expect"))
        {
            if (++expects > 1 || ! equal(f->value, "100-continue") || h->connect)
                return 417;
        }
        else if (! response && h->options && equal(f->name, "Max-Forwards"))
        {
            if (h->has_max_forwards || ! number(f->value, &h->max_forwards))
                return 400;
            h->has_max_forwards = true;
            h->local_options |= h->max_forwards == 0;
        }
        line = end + 2;
    }
    if (line != block + len - 2)
        return 400;
    if (h->chunked && h->has_length)
        return 400;
    if (! response && ! h->http10 && hosts != 1)
        return 400;
    h->close |= h->http10;
    if (! response && h->connect && (h->chunked || (h->has_length && h->length)))
        return 400;
    if (response && (h->status < 200 || h->status == 204) && (h->chunked || h->has_length))
        return 400;
    if (response && h->status == 205)
    {
        if (h->has_length && h->length)
            return 400;
        h->body.reject_data = true;
    }
    if (response && (response_to_head || h->status < 200 || h->status == 204 || h->status == 304))
        h->body.kind = kHpsBodyDone;
    else if (h->chunked)
        h->body.kind = kHpsBodyChunked;
    else if (h->has_length)
    {
        h->body.kind      = h->length ? kHpsBodyFixed : kHpsBodyDone;
        h->body.remaining = h->length;
    }
    else
        h->body.kind = response ? kHpsBodyEof : kHpsBodyDone;
    return 0;
}

static bool hop(const hps_header_t *h, const char *name)
{
    const char *fixed[] = {"Connection",
                           "Proxy-Connection",
                           "Keep-Alive",
                           "TE",
                           "Trailer",
                           "Transfer-Encoding",
                           "Upgrade",
                           "Proxy-Authorization",
                           "Proxy-Authenticate",
                           "Content-Length"};
    for (size_t i = 0; i < ARRAY_SIZE(fixed); ++i)
        if (equal(name, fixed[i]))
            return true;
    for (unsigned i = 0; i < h->count; ++i)
        if (equal(h->fields[i].name, "Connection"))
        {
            bool valid = true;
            if (listContains(h->fields[i].value, name, &valid))
                return true;
        }
    return false;
}

static bool append(char *out, size_t cap, size_t *len, const char *value)
{
    size_t n = stringLength(value);
    if (n >= cap - *len)
        return false;
    memoryCopy(out + *len, value, n + 1);
    *len += n;
    return true;
}

bool hpsRewriteHeader(const hps_header_t *h, bool response, bool client_http10, bool close, char *out, size_t cap,
                      size_t *length)
{
    size_t n = 0;
    char   num[64];
#define ADD(s)                                                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! append(out, cap, &n, (s)))                                                                               \
            return false;                                                                                              \
    } while (0)
    if (response)
    {
        stringNPrintf(num, sizeof(num), "HTTP/1.%c %u ", client_http10 ? '0' : '1', h->status);
        ADD(num);
        ADD(h->reason);
    }
    else
    {
        ADD(h->method);
        ADD(" ");
        if (! *h->target || *h->target == '?')
            ADD("/");
        ADD(h->target);
        ADD(" HTTP/1.1");
    }
    ADD("\r\n");
    if (! response)
    {
        ADD("Host: ");
        ADD(h->authority.wire);
        ADD("\r\n");
    }
    for (unsigned i = 0; i < h->count; ++i)
    {
        const hps_field_t *f = &h->fields[i];
        if (hop(h, f->name) || (! response && (equal(f->name, "Host") || (h->http10 && equal(f->name, "Expect")))))
            continue;
        ADD(f->name);
        ADD(": ");
        if (! response && h->options && equal(f->name, "Max-Forwards"))
        {
            stringNPrintf(num, sizeof(num), "%llu", (unsigned long long) (h->max_forwards - 1));
            ADD(num);
        }
        else
            ADD(f->value);
        ADD("\r\n");
    }
    if (h->has_length)
    {
        stringNPrintf(num, sizeof(num), "Content-Length: %llu\r\n", (unsigned long long) h->length);
        ADD(num);
    }
    else if (h->chunked && ! (response && client_http10))
        ADD("Transfer-Encoding: chunked\r\n");
    ADD(h->http10 ? "Via: 1.0 WaterWall\r\n" : "Via: 1.1 WaterWall\r\n");
    if (close)
        ADD("Connection: close\r\n");
    ADD("\r\n");
    *length = n;
    return true;
#undef ADD
}

static int hex(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = lowerAscii(c);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static bool chunkSize(char *p, uint64_t *value)
{
    uint64_t n = 0;
    if (hex((unsigned char) *p) < 0)
        return false;
    int digit;
    while ((digit = hex((unsigned char) *p)) >= 0)
    {
        if (n > (UINT64_MAX - (unsigned) digit) / 16)
            return false;
        n = n * 16 + (unsigned) digit;
        ++p;
    }
    while (*p)
    {
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p++ != ';')
            return false;
        while (*p == ' ' || *p == '\t')
            ++p;
        char *start = p;
        while (token((unsigned char) *p))
            ++p;
        if (p == start)
            return false;
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p == '=')
        {
            ++p;
            while (*p == ' ' || *p == '\t')
                ++p;
            if (*p == '"')
            {
                ++p;
                while (*p && *p != '"')
                {
                    if (*p == '\\')
                        ++p;
                    if (! *p || ((unsigned char) *p < 32 && *p != '\t') || (unsigned char) *p == 127)
                        return false;
                    ++p;
                }
                if (*p++ != '"')
                    return false;
            }
            else
            {
                start = p;
                while (token((unsigned char) *p))
                    ++p;
                if (p == start)
                    return false;
            }
        }
    }
    *value = n;
    return true;
}

int hpsBodyStep(hps_body_t *b, const unsigned char *data, size_t len, bool decode, const hps_header_t *header,
                size_t *used, bool *emit)
{
    *used = 0;
    *emit = true;
    if (! len || b->kind == kHpsBodyDone)
        return 0;
    if (b->kind == kHpsBodyEof)
    {
        if (b->reject_data)
            return -1;
        *used = len;
        return 1;
    }
    if (b->kind == kHpsBodyFixed || (b->kind == kHpsBodyChunked && b->chunk_phase == 1))
    {
        *used = (size_t) min((uint64_t) len, b->remaining);
        b->remaining -= *used;
        if (! b->remaining)
        {
            if (b->kind == kHpsBodyFixed)
                b->kind = kHpsBodyDone;
            else
                b->chunk_phase = 2;
        }
        return 1;
    }
    *emit = ! decode;
    if (b->chunk_phase == 2)
    {
        if (data[0] != '\r' || (len > 1 && data[1] != '\n'))
            return -1;
        if (len < 2)
            return 0;
        *used          = 2;
        b->chunk_phase = 0;
        return 1;
    }
    size_t n     = 0;
    size_t limit = b->chunk_phase == 3 ? kHpsTrailerLimit : kHpsChunkLineLimit;
    while (n + 1 < len && ! (data[n] == '\r' && data[n + 1] == '\n'))
        ++n;
    if (n + 1 == len || len == 1)
        return len >= limit ? -1 : 0;
    if (n + 2 > limit || memchr(data, 0, n))
        return -1;
    char line[kHpsTrailerLimit + 1];
    memoryCopy(line, data, n);
    line[n] = 0;
    if (b->chunk_phase == 3)
    {
        if (n + 2 > kHpsTrailerLimit - b->trailer_bytes)
            return -1;
        b->trailer_bytes += (unsigned) n + 2;
        if (! n)
            b->kind = kHpsBodyDone;
        else
        {
            hps_field_t f;
            if (++b->trailer_fields > kHpsTrailerFields || ! field(line, &f))
                return -1;
            if (header && hop(header, f.name))
                return -1;
            const char *forbidden[] = {"Content-Length",
                                       "Transfer-Encoding",
                                       "Host",
                                       "Connection",
                                       "Trailer",
                                       "Authorization",
                                       "Proxy-Authorization",
                                       "Proxy-Authenticate",
                                       "TE",
                                       "Upgrade",
                                       "Keep-Alive",
                                       "Proxy-Connection",
                                       "Content-Encoding",
                                       "Content-Type",
                                       "Content-Range"};
            for (size_t i = 0; i < ARRAY_SIZE(forbidden); ++i)
                if (equal(f.name, forbidden[i]))
                    return -1;
        }
    }
    else
    {
        if (! chunkSize(line, &b->remaining))
            return -1;
        if (b->reject_data && b->remaining)
            return -1;
        b->chunk_phase = b->remaining ? 1 : 3;
    }
    *used = n + 2;
    return 1;
}

static int base64(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

bool hpsDecodeBasic(const char *value, char username[256], char password[256], char key[512])
{
    if (! value || stringLength(value) < 7)
        return false;
    char scheme[6];
    memoryCopy(scheme, value, 5);
    scheme[5] = 0;
    if (! equal(scheme, "Basic") || value[5] != ' ')
        return false;
    value += 6;
    while (*value == ' ')
        ++value;
    size_t len = stringLength(value), n = 0;
    if (! len || len % 4 || len > 684)
        return false;
    for (size_t i = 0; i < len; i += 4)
    {
        int      a = base64((unsigned char) value[i]), b = base64((unsigned char) value[i + 1]);
        int      c = base64((unsigned char) value[i + 2]), d = base64((unsigned char) value[i + 3]);
        unsigned bytes = value[i + 2] == '=' ? 1 : value[i + 3] == '=' ? 2 : 3;
        if (a < 0 || b < 0 || (bytes > 1 && c < 0) || (bytes > 2 && d < 0) || (bytes < 3 && i + 4 != len) ||
            (bytes == 1 && (value[i + 3] != '=' || (b & 15))) || (bytes == 2 && (c & 3)) || n + bytes > 511)
            return false;
        key[n++] = (char) ((a << 2) | (b >> 4));
        if (bytes > 1)
            key[n++] = (char) ((b << 4) | (c >> 2));
        if (bytes > 2)
            key[n++] = (char) ((c << 6) | d);
    }
    key[n] = 0;
    for (size_t i = 0; i < n; ++i)
        if ((unsigned char) key[i] < 32 || (unsigned char) key[i] == 127)
            return false;
    char *colon = stringChr(key, ':');
    if (! colon || colon == key || (size_t) (colon - key) > 255 || ! colon[1] || stringLength(colon + 1) > 255)
        return false;
    memoryCopy(username, key, (size_t) (colon - key));
    username[colon - key] = 0;
    stringCopy(password, colon + 1);
    return true;
}
