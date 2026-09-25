#include "parser.h"

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
        if (hpHeaderIsHop(h, f->name) ||
            (! response && (hpAsciiEqual(f->name, "Host") || (h->http10 && hpAsciiEqual(f->name, "Expect")))))
            continue;
        ADD(f->name);
        ADD(": ");
        if (! response && h->options && hpAsciiEqual(f->name, "Max-Forwards"))
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

bool hpsDecodeBasic(const char *value, char username[256], char password[256], char key[512])
{
    if (! value || stringLength(value) < 7)
        return false;
    char scheme[6];
    memoryCopy(scheme, value, 5);
    scheme[5] = 0;
    if (! hpAsciiEqual(scheme, "Basic") || value[5] != ' ')
        return false;
    value += 6;
    while (*value == ' ')
        ++value;
    size_t len = stringLength(value);
    if (! len || len > BASE64_ENCODE_OUT_SIZE(511))
        return false;
    int decoded = wwBase64DecodeCanonical(value, (unsigned int) len, (unsigned char *) key, 511);
    if (decoded < 0)
        return false;
    size_t n = (size_t) decoded;
    key[n]   = 0;
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
