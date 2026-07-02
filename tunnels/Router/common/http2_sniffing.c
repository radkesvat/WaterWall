#include "http2_sniffing.h"

#include "generic_sniffer.h"

#include <nghttp2/nghttp2.h>

enum
{
    kRouterHttp2PrefaceLen = 24U
};

static const uint8_t kRouterHttp2Preface[kRouterHttp2PrefaceLen] = {
    'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2',
    '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
};

typedef struct router_http2_sniff_ctx_s
{
    bool authority_seen;
    bool authority_valid;
    bool host_valid;

    uint8_t  authority[UINT8_MAX + 1U];
    uint32_t authority_len;
    uint8_t  host[UINT8_MAX + 1U];
    uint32_t host_len;
} router_http2_sniff_ctx_t;

static bool routerHttp2HeaderNameEquals(const uint8_t *name, size_t namelen, const char *expected)
{
    size_t expected_len = stringLength(expected);
    return namelen == expected_len && memoryCompare(name, expected, expected_len) == 0;
}

static bool routerHttp2NormalizeHost(const uint8_t *value, size_t value_len, uint8_t out[UINT8_MAX + 1U],
                                     uint32_t *out_len)
{
    if (value == NULL || value_len > UINT32_MAX)
    {
        return false;
    }

    const uint8_t *host     = value;
    uint32_t       host_len = (uint32_t) value_len;
    genericsnifferStripHostPortAndDot(&host, &host_len);
    if (host_len == 0 || host_len > UINT8_MAX)
    {
        return false;
    }

    memoryCopy(out, host, host_len);
    out[host_len] = '\0';
    *out_len      = host_len;
    return true;
}

static int routerHttp2OnHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                       size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                                       void *user_data)
{
    (void) session;
    (void) flags;

    if (frame == NULL || frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    router_http2_sniff_ctx_t *ctx = user_data;

    if (routerHttp2HeaderNameEquals(name, namelen, ":authority"))
    {
        if (! ctx->authority_seen)
        {
            ctx->authority_valid =
                routerHttp2NormalizeHost(value, valuelen, ctx->authority, &ctx->authority_len);
        }
        ctx->authority_seen = true;
        return 0;
    }

    if (! ctx->authority_seen && ! ctx->host_valid && routerHttp2HeaderNameEquals(name, namelen, "host"))
    {
        ctx->host_valid = routerHttp2NormalizeHost(value, valuelen, ctx->host, &ctx->host_len);
    }

    return 0;
}

static router_http2_domain_result_t routerHttp2NeedMoreOrMissing(uint32_t payload_len)
{
    return payload_len < (uint32_t) kGenericSnifferMaxWindowBytes ? kRouterHttp2DomainNeedMore
                                                                 : kRouterHttp2DomainMissing;
}

router_http2_domain_result_t routerHttp2SniffDomain(const uint8_t *payload, uint32_t payload_len, uint8_t *host,
                                                    uint32_t host_cap, uint32_t *host_len)
{
    if ((payload == NULL && payload_len > 0) || host == NULL || host_cap == 0 || host_len == NULL)
    {
        return kRouterHttp2DomainMissing;
    }

    host[0]   = '\0';
    *host_len = 0;

    if (payload_len == 0)
    {
        return routerHttp2NeedMoreOrMissing(payload_len);
    }

    uint32_t compare_len = payload_len < kRouterHttp2PrefaceLen ? payload_len : kRouterHttp2PrefaceLen;
    if (memoryCompare(payload, kRouterHttp2Preface, compare_len) != 0)
    {
        return kRouterHttp2DomainMissing;
    }

    if (payload_len < kRouterHttp2PrefaceLen)
    {
        return routerHttp2NeedMoreOrMissing(payload_len);
    }

    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_session           *session   = NULL;
    router_http2_sniff_ctx_t   ctx       = {0};

    if (nghttp2_session_callbacks_new(&callbacks) != 0)
    {
        return kRouterHttp2DomainMissing;
    }

    nghttp2_session_callbacks_set_on_header_callback(callbacks, routerHttp2OnHeaderCallback);

    int rc = nghttp2_session_server_new(&session, callbacks, &ctx);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0)
    {
        return kRouterHttp2DomainMissing;
    }

    nghttp2_ssize consumed = nghttp2_session_mem_recv2(session, payload, payload_len);
    nghttp2_session_del(session);
    if (consumed < 0)
    {
        return kRouterHttp2DomainMissing;
    }

    const uint8_t *found     = NULL;
    uint32_t       found_len = 0;
    if (ctx.authority_seen)
    {
        if (ctx.authority_valid)
        {
            found     = ctx.authority;
            found_len = ctx.authority_len;
        }
    }
    else if (ctx.host_valid)
    {
        found     = ctx.host;
        found_len = ctx.host_len;
    }

    if (found != NULL)
    {
        if (found_len >= host_cap)
        {
            return kRouterHttp2DomainMissing;
        }

        memoryCopy(host, found, found_len);
        host[found_len] = '\0';
        *host_len       = found_len;
        return kRouterHttp2DomainFound;
    }

    return routerHttp2NeedMoreOrMissing(payload_len);
}
