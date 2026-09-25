#include "loggers/network_logger.h"
#include "structure.h"

static bool integer(const cJSON *json, const char *name, int64_t def, int64_t low, int64_t high, uint32_t *out)
{
    int64_t n = def;
    if (jsonGetObjectIntegerInRange(json, name, low, high, &n) == kJsonValueInvalid)
        return false;
    *out = (uint32_t) n;
    return true;
}
static bool credential(const cJSON *v, bool username)
{
    if (! cJSON_IsString(v))
        return false;
    size_t n = stringLength(v->valuestring);
    if (! n || n > 255)
        return false;
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char c = (unsigned char) v->valuestring[i];
        if (c < 32 || c == 127 || (username && c == ':'))
            return false;
    }
    return true;
}
static bool token(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           (c && stringChr("!#$%&'*+-.^_`|~", c));
}
static bool extraHeaders(hpc_tstate_t *ts, const cJSON *headers)
{
    if (! headers)
    {
        ts->headers = stringDuplicate("");
        return ts->headers != NULL;
    }
    if (! cJSON_IsObject(headers))
        return false;
    size_t       length = 0;
    const cJSON *f;
    const char  *owned[] = {"Host",
                            "Proxy-Authorization",
                            "Content-Length",
                            "Transfer-Encoding",
                            "Connection",
                            "Proxy-Connection",
                            "Keep-Alive",
                            "TE",
                            "Trailer",
                            "Upgrade",
                            "Expect"};
    cJSON_ArrayForEach(f, headers)
    {
        if (! f->string[0] || ! cJSON_IsString(f))
            return false;
        for (const unsigned char *p = (const unsigned char *) f->string; *p; ++p)
            if (! token(*p))
                return false;
        for (const unsigned char *p = (const unsigned char *) f->valuestring; *p; ++p)
            if ((*p < 32 && *p != '\t') || *p == 127)
                return false;
        for (size_t i = 0; i < ARRAY_SIZE(owned); ++i)
            if (hpAsciiEqual(f->string, owned[i]))
                return false;
        for (const cJSON *o = f->next; o; o = o->next)
            if (hpAsciiEqual(f->string, o->string))
                return false;
        size_t name_length = stringLength(f->string), value_length = stringLength(f->valuestring);
        if (name_length > ts->max_header - 4 || value_length > ts->max_header - 4 - name_length)
            return false;
        size_t n = name_length + value_length + 4;
        if (n > ts->max_header - length)
            return false;
        length += n;
    }
    ts->headers = memoryAllocate(length + 1);
    if (! ts->headers)
        return false;
    size_t at = 0;
    cJSON_ArrayForEach(f, headers) at +=
        (size_t) stringNPrintf(ts->headers + at, length + 1 - at, "%s: %s\r\n", f->string, f->valuestring);
    ts->headers[length] = 0;
    return true;
}
static bool domainStrategy(hpc_tstate_t *ts, const cJSON *value)
{
    static const char         *names[]      = {"do-not-resolve-domains",
                                               "resolve-domains-and-accept-dns-returned-order",
                                               "resolve-domains-and-prefer-ipv4",
                                               "resolve-domains-and-prefer-ipv6",
                                               "resolve-domains-and-use-only-ipv4",
                                               "resolve-domains-and-use-only-ipv6",
                                               "resolve-domains-with-core-settings"};
    const enum domain_strategy strategies[] = {
        kDsInvalid, kDsInvalid, kDsPreferIpV4, kDsPreferIpV6, kDsOnlyIpV4, kDsOnlyIpV6, GSTATE.domain_strategy};
    if (! value)
        return true;
    if (cJSON_IsString(value))
        for (size_t i = 0; i < ARRAY_SIZE(names); ++i)
            if (! stringCompare(value->valuestring, names[i]))
            {
                if (i && ! ts->connect)
                {
                    LOGF("HttpProxyClient: resolving domain-strategy requires mode connect");
                    return false;
                }
                ts->resolve_domains = i != 0;
                ts->domain_strategy = strategies[i];
                return true;
            }
    LOGF("HttpProxyClient: domain-strategy must be a supported non-empty lowercase string");
    return false;
}
bool hpcParseSettings(hpc_tstate_t *ts, node_t *node)
{
    const cJSON *json = node->node_settings_json, *f;
    if (! cJSON_IsObject(json) || ! nodeHasNext(node))
        return false;
    const char *keys[] = {"mode",
                          "domain-strategy",
                          "target-address",
                          "port",
                          "username",
                          "password",
                          "method",
                          "path",
                          "body-mode",
                          "content-length",
                          "headers",
                          "max-header-bytes",
                          "header-timeout-ms",
                          "connect-response-timeout-ms",
                          "idle-timeout-ms",
                          "verbose"};
    cJSON_ArrayForEach(f, json)
    {
        bool known = false;
        for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
            known |= ! stringCompare(f->string, keys[i]);
        if (! known)
            return false;
        for (const cJSON *o = f->next; o; o = o->next)
            if (! stringCompare(f->string, o->string))
            {
                LOGF("HttpProxyClient: duplicate setting %s", f->string);
                return false;
            }
    }
#define GET(key) cJSON_GetObjectItemCaseSensitive(json, key)
    f = GET("mode");
    if (f &&
        (! cJSON_IsString(f) || (stringCompare(f->valuestring, "connect") && stringCompare(f->valuestring, "http"))))
        return false;
    ts->connect = ! f || ! stringCompare(f->valuestring, "connect");
    if (! domainStrategy(ts, GET("domain-strategy")))
        return false;
    f = GET("verbose");
    if (f && ! cJSON_IsBool(f))
        return false;
    ts->verbose = cJSON_IsTrue(f);
    if (! integer(json, "max-header-bytes", 32768, 1024, 65536, &ts->max_header) ||
        ! integer(json, "header-timeout-ms", 15000, 1, INT32_MAX, &ts->header_timeout) ||
        ! integer(json, "connect-response-timeout-ms", 30000, 1, INT32_MAX, &ts->connect_timeout) ||
        ! integer(json, "idle-timeout-ms", 300000, 1, INT32_MAX, &ts->idle_timeout))
        return false;
    f = GET("target-address");
    if (! cJSON_IsString(f) || ! f->valuestring[0] || stringLength(f->valuestring) > 255)
        return false;
    ts->dynamic_address = ! stringCompare(f->valuestring, "dest_context->address");
    ts->target          = stringDuplicate(f->valuestring);
    if (! ts->target)
        return false;
    f                = GET("port");
    ts->dynamic_port = cJSON_IsString(f) && ! stringCompare(f->valuestring, "dest_context->port");
    int64_t port;
    if (! ts->dynamic_port)
    {
        if (! jsonGetIntegerInRange(f, 1, 65535, &port))
            return false;
        ts->port = (uint16_t) port;
    }
    if (! ts->dynamic_address)
    {
        char            wire[272];
        hps_authority_t authority;
        bool            bracket = stringChr(ts->target, ':') && ts->target[0] != '[';
        int n = stringNPrintf(wire, sizeof(wire), bracket ? "[%s]:%u" : "%s:%u", ts->target, ts->port ? ts->port : 80);
        if (n < 0 || (size_t) n >= sizeof(wire) || ! hpsAuthority(wire, (size_t) n, true, &authority))
            return false;
    }
    const cJSON *u = GET("username"), *p = GET("password");
    if (u || p)
    {
        if (! credential(u, true) || ! credential(p, false))
            return false;
        unsigned char plain[512];
        int           n = stringNPrintf((char *) plain, sizeof(plain), "%s:%s", u->valuestring, p->valuestring);
        assert(n > 0 && n <= 511);
        wwBase64Encode(plain, (unsigned) n, ts->authorization);
        ts->authorization[4 * (((unsigned) n + 2) / 3)] = 0;
        memoryZero(plain, sizeof(plain));
    }
    if (ts->connect)
    {
        if (GET("method") || GET("path") || GET("body-mode") || GET("content-length"))
            return false;
        stringCopy(ts->method, "CONNECT");
    }
    else
    {
        if (GET("connect-response-timeout-ms"))
            return false;
        const char *methods[] = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
        f                     = GET("method");
        if (f && ! cJSON_IsString(f))
            return false;
        const char *m     = f ? f->valuestring : "POST";
        bool        valid = false;
        for (size_t i = 0; i < ARRAY_SIZE(methods); ++i)
            valid |= ! stringCompare(m, methods[i]);
        if (! valid)
            return false;
        stringCopy(ts->method, m);
        f = GET("path");
        if (f && ! cJSON_IsString(f))
            return false;
        const char *path = f ? f->valuestring : "/";
        if (path[0] != '/' || stringLength(path) > kHpsRequestLineLimit)
            return false;
        for (const unsigned char *c = (const unsigned char *) path; *c; ++c)
        {
            if (*c <= 32 || *c >= 127 || *c == '#' || *c == '\\')
                return false;
            if (*c == '%')
            {
                if (! c[1] || ! c[2] || asciiHexValue(c[1]) < 0 || asciiHexValue(c[2]) < 0)
                    return false;
                c += 2;
            }
        }
        ts->path = stringDuplicate(path);
        if (! ts->path)
            return false;
        f = GET("body-mode");
        if (f && ! cJSON_IsString(f))
            return false;
        const char *body = f ? f->valuestring : "chunked";
        if (! stringCompare(body, "none"))
            ts->upload = kHpcBodyNone;
        else if (! stringCompare(body, "fixed"))
            ts->upload = kHpcBodyFixed;
        else if (! stringCompare(body, "chunked"))
            ts->upload = kHpcBodyChunked;
        else
            return false;
        if (! stringCompare(m, "HEAD") && ts->upload != kHpcBodyNone)
            return false;
        f = GET("content-length");
        int64_t length;
        if (ts->upload == kHpcBodyFixed)
        {
            if (! jsonGetIntegerInRange(f, 0, INT64_C(9007199254740991), &length))
                return false;
            ts->content_length = (uint64_t) length;
        }
        else if (f)
            return false;
    }
    return extraHeaders(ts, GET("headers"));
#undef GET
}
