#include "structure.h"

#include "loggers/network_logger.h"
#include "utils/sha1.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>

typedef struct httpclient_h1_response_info_s
{
    int     status_code;
    bool    transfer_chunked;
    bool    connection_upgrade;
    bool    has_upgrade_header;
    bool    upgrade_h2c;
    bool    upgrade_websocket;
    bool    has_content_length;
    bool    has_sec_websocket_accept;
    bool    has_sec_websocket_protocol;
    bool    has_sec_websocket_extensions;
    int64_t content_length;
    char    sec_websocket_accept[128];
    char    sec_websocket_protocol[128];
    char    sec_websocket_extensions[256];
    char    upgrade_value[256];
} httpclient_h1_response_info_t;

enum
{
    kWebSocketOpcodeContinuation = 0x0,
    kWebSocketOpcodeText         = 0x1,
    kWebSocketOpcodeBinary       = 0x2,
    kWebSocketOpcodeClose        = 0x8,
    kWebSocketOpcodePing         = 0x9,
    kWebSocketOpcodePong         = 0xA
};

static const char *kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static bool httpclientVerboseEnabled(tunnel_t *t)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    return ts->verbose;
}

static const char *httpclientWebSocketOpcodeName(uint8_t opcode)
{
    switch (opcode)
    {
    case kWebSocketOpcodeContinuation:
        return "continuation";
    case kWebSocketOpcodeText:
        return "text";
    case kWebSocketOpcodeBinary:
        return "binary";
    case kWebSocketOpcodeClose:
        return "close";
    case kWebSocketOpcodePing:
        return "ping";
    case kWebSocketOpcodePong:
        return "pong";
    default:
        return "unknown";
    }
}

static bool parseContentLength(const char *value, int64_t *out)
{
    if (value == NULL || out == NULL)
    {
        return false;
    }

    while (*value == ' ' || *value == '\t')
    {
        ++value;
    }

    if (*value == '\0')
    {
        return false;
    }

    char               *endp = NULL;
    unsigned long long  v    = strtoull(value, &endp, 10);
    if (endp == value)
    {
        return false;
    }

    while (endp != NULL && (*endp == ' ' || *endp == '\t'))
    {
        ++endp;
    }

    if (endp == NULL || *endp != '\0')
    {
        return false;
    }

    if (v > (unsigned long long) INT64_MAX)
    {
        return false;
    }

    *out = (int64_t) v;
    return true;
}

static bool appendHeaderFmt(char *buf, size_t cap, int *offset, const char *fmt, ...)
{
    if (buf == NULL || offset == NULL || fmt == NULL || *offset < 0 || (size_t) *offset >= cap)
    {
        return false;
    }

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + *offset, cap - (size_t) *offset, fmt, args);
    va_end(args);

    if (written < 0)
    {
        return false;
    }

    if ((size_t) written >= cap - (size_t) *offset)
    {
        return false;
    }

    *offset += written;
    return true;
}

static bool httpclientHeaderNameEquals(const char *value, const char *name)
{
    return httpclientStringCaseEquals(value, name);
}

static const char *httpclientUpgradeProtocol(const httpclient_tstate_t *ts)
{
    if (ts == NULL || ts->upgrade_protocol == NULL || ts->upgrade_protocol[0] == '\0')
    {
        return "h2c";
    }

    return ts->upgrade_protocol;
}

static bool httpclientUpgradeIsH2C(const httpclient_tstate_t *ts)
{
    return ts != NULL && httpclientStringCaseEquals(httpclientUpgradeProtocol(ts), "h2c");
}

static bool httpclientUpgradeIsCustom(const httpclient_tstate_t *ts)
{
    return ts != NULL && ! httpclientUpgradeIsH2C(ts);
}

static bool httpclientShouldSkipExtraHeader(const char *name, bool upgrade_to_h2, bool websocket_mode)
{
    if (name == NULL)
    {
        return true;
    }

    if (httpclientHeaderNameEquals(name, "host") || httpclientHeaderNameEquals(name, "user-agent") ||
        httpclientHeaderNameEquals(name, "accept") || httpclientHeaderNameEquals(name, "content-length"))
    {
        return true;
    }

    if (websocket_mode)
    {
        return httpclientHeaderNameEquals(name, "connection") || httpclientHeaderNameEquals(name, "upgrade") ||
               httpclientHeaderNameEquals(name, "sec-websocket-key") ||
               httpclientHeaderNameEquals(name, "sec-websocket-version") ||
               httpclientHeaderNameEquals(name, "sec-websocket-protocol") ||
               httpclientHeaderNameEquals(name, "sec-websocket-extensions") ||
               httpclientHeaderNameEquals(name, "origin") || httpclientHeaderNameEquals(name, "http2-settings");
    }

    if (upgrade_to_h2)
    {
        return httpclientHeaderNameEquals(name, "connection") || httpclientHeaderNameEquals(name, "upgrade") ||
               httpclientHeaderNameEquals(name, "http2-settings");
    }

    return httpclientHeaderNameEquals(name, "connection") || httpclientHeaderNameEquals(name, "transfer-encoding");
}

static bool httpclientShouldSkipUpgradeExtraHeader(const char *name)
{
    if (name == NULL)
    {
        return true;
    }

    return httpclientHeaderNameEquals(name, "connection") || httpclientHeaderNameEquals(name, "upgrade") ||
           httpclientHeaderNameEquals(name, "http2-settings");
}

static bool httpclientFindHeaderValue(const char *headers, const char *name, char *out, size_t out_cap)
{
    if (headers == NULL || name == NULL || out == NULL || out_cap == 0)
    {
        return false;
    }

    out[0] = '\0';

    const char *line = strstr(headers, "\r\n");
    if (line == NULL)
    {
        return false;
    }
    line += 2;

    while (*line != '\0')
    {
        const char *next = strstr(line, "\r\n");
        if (next == NULL)
        {
            break;
        }

        if (next == line)
        {
            break;
        }

        const char *colon = strchr(line, ':');
        if (colon != NULL && colon < next)
        {
            size_t key_len = (size_t) (colon - line);
            if (strlen(name) == key_len)
            {
                bool match = true;
                for (size_t i = 0; i < key_len; ++i)
                {
                    if ((char) tolower((unsigned char) line[i]) != (char) tolower((unsigned char) name[i]))
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    const char *value_begin = colon + 1;
                    while (value_begin < next && (*value_begin == ' ' || *value_begin == '\t'))
                    {
                        ++value_begin;
                    }

                    const char *value_end = next;
                    while (value_end > value_begin && (value_end[-1] == ' ' || value_end[-1] == '\t'))
                    {
                        --value_end;
                    }

                    size_t value_len = (size_t) (value_end - value_begin);
                    if (value_len >= out_cap)
                    {
                        value_len = out_cap - 1U;
                    }

                    memoryCopy(out, value_begin, value_len);
                    out[value_len] = '\0';
                    return true;
                }
            }
        }

        line = next + 2;
    }

    return false;
}

static bool httpclientValidateRequiredHeaders(const char *headers, const cJSON *required)
{
    if (! cJSON_IsObject(required))
    {
        return true;
    }

    char found_value[1024];

    cJSON *header = NULL;
    cJSON_ArrayForEach(header, required)
    {
        if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
        {
            continue;
        }

        if (httpclientShouldSkipUpgradeExtraHeader(header->string))
        {
            continue;
        }

        if (! httpclientFindHeaderValue(headers, header->string, found_value, sizeof(found_value)))
        {
            return false;
        }

        if (! httpclientStringCaseEquals(found_value, header->valuestring))
        {
            return false;
        }
    }

    return true;
}

static void httpclientBuildWebSocketAccept(const char *key, char *out, size_t out_cap)
{
    char digest_input[160];
    int  input_len = snprintf(digest_input, sizeof(digest_input), "%s%s", key, kWebSocketGuid);
    if (input_len <= 0 || (size_t) input_len >= sizeof(digest_input) || out_cap == 0)
    {
        if (out_cap > 0)
        {
            out[0] = '\0';
        }
        return;
    }

    unsigned char digest[20];
    wwSHA1((unsigned char *) digest_input, (uint32_t) input_len, digest);

    if (out_cap <= BASE64_ENCODE_OUT_SIZE(sizeof(digest)))
    {
        out[0] = '\0';
        return;
    }

    int encoded = wwBase64Encode(digest, sizeof(digest), out);
    if (encoded < 0 || (size_t) encoded >= out_cap)
    {
        out[0] = '\0';
        return;
    }
    out[encoded] = '\0';
}

static bool httpclientGenerateWebSocketKey(httpclient_lstate_t *ls)
{
    uint8_t raw_key[16];
    getRandomBytes(raw_key, sizeof(raw_key));

    int encoded = wwBase64Encode(raw_key, sizeof(raw_key), ls->websocket_key);
    if (encoded <= 0 || encoded >= (int) sizeof(ls->websocket_key))
    {
        ls->websocket_key[0] = '\0';
        return false;
    }

    ls->websocket_key[encoded] = '\0';
    return true;
}

static bool sendBytesUp(tunnel_t *t, line_t *l, const void *data, uint32_t len)
{
    if (len == 0)
    {
        return true;
    }

    buffer_pool_t *pool      = lineGetBufferPool(l);
    uint32_t       max_chunk = bufferpoolGetLargeBufferSize(pool);
    if (max_chunk == 0)
    {
        return false;
    }

    const uint8_t *ptr = (const uint8_t *) data;
    uint32_t       rem = len;

    while (rem > 0)
    {
        uint32_t chunk = min(rem, max_chunk);
        sbuf_t  *buf   = allocBufferForLength(l, chunk);

        sbufSetLength(buf, chunk);
        sbufWriteLarge(buf, ptr, chunk);

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
        {
            return false;
        }

        ptr += chunk;
        rem -= chunk;
    }

    return true;
}

static bool sendTextUp(tunnel_t *t, line_t *l, const char *text)
{
    return sendBytesUp(t, l, text, (uint32_t) strlen(text));
}

static bool httpclientSendRawUp(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return true;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        return httpclientTransportSendHttp2DataFrame(t, l, ls, buf, false);
    }

    return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf);
}

static bool httpclientSendRawBytesUp(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, const void *data, uint32_t len)
{
    if (len == 0)
    {
        return true;
    }

    if (ls->runtime_proto == kHttpClientRuntimeHttp2)
    {
        sbuf_t *buf = allocBufferForLength(l, len);
        sbufSetLength(buf, len);
        sbufWriteLarge(buf, data, len);
        return httpclientTransportSendHttp2DataFrame(t, l, ls, buf, false);
    }

    return sendBytesUp(t, l, data, len);
}

static size_t httpclientBuildWebSocketHeader(uint8_t *header, size_t cap, uint8_t opcode, uint64_t payload_len,
                                             bool masked, const uint8_t mask_key[4])
{
    if (cap < 2)
    {
        return 0;
    }

    size_t off   = 0;
    header[off++] = (uint8_t) (0x80U | (opcode & 0x0FU));

    uint8_t len_byte = masked ? 0x80U : 0x00U;
    if (payload_len <= 125U)
    {
        header[off++] = (uint8_t) (len_byte | (uint8_t) payload_len);
    }
    else if (payload_len <= 0xFFFFU)
    {
        if (cap < off + 3)
        {
            return 0;
        }
        header[off++] = (uint8_t) (len_byte | 126U);
        header[off++] = (uint8_t) ((payload_len >> 8) & 0xFFU);
        header[off++] = (uint8_t) (payload_len & 0xFFU);
    }
    else
    {
        if (cap < off + 9)
        {
            return 0;
        }
        header[off++] = (uint8_t) (len_byte | 127U);
        for (int shift = 56; shift >= 0; shift -= 8)
        {
            header[off++] = (uint8_t) ((payload_len >> shift) & 0xFFU);
        }
    }

    if (masked)
    {
        if (cap < off + 4 || mask_key == NULL)
        {
            return 0;
        }

        memoryCopy(header + off, mask_key, 4);
        off += 4;
    }

    return off;
}

static void httpclientMaskWebSocketPayload(sbuf_t *payload, const uint8_t mask_key[4])
{
    if (payload == NULL || mask_key == NULL)
    {
        return;
    }

    uint8_t *ptr = (uint8_t *) sbufGetMutablePtr(payload);
    uint32_t len = sbufGetLength(payload);
    for (uint32_t i = 0; i < len; ++i)
    {
        ptr[i] ^= mask_key[i & 3U];
    }
}

static bool httpclientSendWebSocketControlFrame(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, uint8_t opcode,
                                                const void *payload, uint32_t payload_len)
{
    uint8_t header[16];
    uint8_t mask_key[4] = {0};
    getRandomBytes(mask_key, sizeof(mask_key));

    size_t header_len =
        httpclientBuildWebSocketHeader(header, sizeof(header), opcode, payload_len, true, mask_key);
    if (header_len == 0)
    {
        return false;
    }

    if (! httpclientSendRawBytesUp(t, l, ls, header, (uint32_t) header_len))
    {
        return false;
    }

    if (payload_len == 0)
    {
        return true;
    }

    sbuf_t *buf = allocBufferForLength(l, payload_len);
    sbufSetLength(buf, payload_len);
    sbufWriteLarge(buf, payload, payload_len);
    httpclientMaskWebSocketPayload(buf, mask_key);
    return httpclientSendRawUp(t, l, ls, buf);
}

static const char *httpclientSplitDirectionValue(const httpclient_tstate_t *ts, httpclient_split_role_t role)
{
    return role == kHttpClientSplitRoleDownload ? ts->split_download_value : ts->split_upload_value;
}

static const char *httpclientSplitMethod(const httpclient_tstate_t *ts, httpclient_split_role_t role)
{
    return role == kHttpClientSplitRoleDownload ? ts->split_download_method : ts->split_upload_method;
}

static const char *httpclientSplitPath(const httpclient_tstate_t *ts, httpclient_split_role_t role)
{
    return role == kHttpClientSplitRoleDownload ? ts->split_download_path : ts->split_upload_path;
}

static enum http_method httpclientEffectiveMethodEnum(const httpclient_tstate_t *ts, const httpclient_lstate_t *ls)
{
    if (ls->split_role == kHttpClientSplitRoleDownload)
    {
        return ts->split_download_method_enum;
    }
    if (ls->split_role == kHttpClientSplitRoleUpload)
    {
        return ts->split_upload_method_enum;
    }
    return ts->method_enum;
}

static bool httpclientAppendString(char *dst, size_t cap, size_t *offset, const char *value)
{
    size_t len = value == NULL ? 0 : strlen(value);
    if (*offset + len >= cap)
    {
        return false;
    }

    if (len > 0)
    {
        memoryCopy(dst + *offset, value, len);
        *offset += len;
    }
    dst[*offset] = '\0';
    return true;
}

static bool httpclientAppendQueryParam(char *path, size_t cap, size_t *off, bool first, const char *name,
                                       const char *value)
{
    char sep[2] = {first ? '?' : '&', '\0'};
    return httpclientAppendString(path, cap, off, sep) && httpclientAppendString(path, cap, off, name) &&
           httpclientAppendString(path, cap, off, "=") && httpclientAppendString(path, cap, off, value);
}

static char *httpclientBuildSplitPath(const httpclient_tstate_t *ts, const httpclient_lstate_t *ls)
{
    const char *base      = httpclientSplitPath(ts, ls->split_role);
    const char *direction = httpclientSplitDirectionValue(ts, ls->split_role);
    const char *id        = ls->split_id;
    const char *token     = ts->split_token == NULL ? "" : ts->split_token;

    char cache_value[32];
    snprintf(cache_value, sizeof(cache_value), "%016" PRIx64, fastRand64());

    size_t cap = strlen(base) + (strlen(id) * 2U) + (strlen(direction) * 2U) + (strlen(cache_value) * 2U) +
                 (strlen(token) * 2U) +
                 strlen(ts->split_id_name) + strlen(ts->split_direction_name) +
                 strlen(ts->split_cache_bypass_name) + 128;
    char *path = memoryAllocate(cap);
    size_t off = 0;

    for (size_t i = 0; base[i] != '\0';)
    {
        if (strncmp(base + i, "{id}", 4) == 0)
        {
            if (! httpclientAppendString(path, cap, &off, id))
            {
                memoryFree(path);
                return NULL;
            }
            i += 4;
            continue;
        }
        if (strncmp(base + i, "{direction}", 11) == 0)
        {
            if (! httpclientAppendString(path, cap, &off, direction))
            {
                memoryFree(path);
                return NULL;
            }
            i += 11;
            continue;
        }
        if (strncmp(base + i, "{cache}", 7) == 0)
        {
            if (! httpclientAppendString(path, cap, &off, cache_value))
            {
                memoryFree(path);
                return NULL;
            }
            i += 7;
            continue;
        }
        if (strncmp(base + i, "{token}", 7) == 0)
        {
            if (! httpclientAppendString(path, cap, &off, token))
            {
                memoryFree(path);
                return NULL;
            }
            i += 7;
            continue;
        }

        if (off + 1 >= cap)
        {
            memoryFree(path);
            return NULL;
        }
        path[off++] = base[i++];
        path[off]   = '\0';
    }

    bool has_query = strchr(path, '?') != NULL;
    bool first     = ! has_query;

    if (ts->split_id_placement == kHttpClientSplitPlacementQuery)
    {
        if (! httpclientAppendQueryParam(path, cap, &off, first, ts->split_id_name, id))
        {
            memoryFree(path);
            return NULL;
        }
        first = false;
    }

    if (ts->split_direction_placement == kHttpClientSplitPlacementQuery)
    {
        if (! httpclientAppendQueryParam(path, cap, &off, first, ts->split_direction_name, direction))
        {
            memoryFree(path);
            return NULL;
        }
        first = false;
    }

    if (ts->split_cache_bypass)
    {
        if (! httpclientAppendQueryParam(path, cap, &off, first, ts->split_cache_bypass_name, cache_value))
        {
            memoryFree(path);
            return NULL;
        }
    }

    return path;
}

static bool httpclientAppendSplitPlacementHeaders(char *header_buf, size_t cap, int *offset,
                                                  const httpclient_tstate_t *ts, const httpclient_lstate_t *ls)
{
    const char *direction = httpclientSplitDirectionValue(ts, ls->split_role);

    if (ts->split_id_placement == kHttpClientSplitPlacementHeader &&
        ! appendHeaderFmt(header_buf, cap, offset, "%s: %s\r\n", ts->split_id_name, ls->split_id))
    {
        return false;
    }

    if (ts->split_direction_placement == kHttpClientSplitPlacementHeader &&
        ! appendHeaderFmt(header_buf, cap, offset, "%s: %s\r\n", ts->split_direction_name, direction))
    {
        return false;
    }

    if (ts->split_token != NULL && ts->split_token_placement == kHttpClientSplitPlacementHeader &&
        ! appendHeaderFmt(header_buf, cap, offset, "%s: %s\r\n", ts->split_token_name, ts->split_token))
    {
        return false;
    }

    bool needs_cookie = ts->split_id_placement == kHttpClientSplitPlacementCookie ||
                        ts->split_direction_placement == kHttpClientSplitPlacementCookie ||
                        (ts->split_token != NULL && ts->split_token_placement == kHttpClientSplitPlacementCookie);
    if (! needs_cookie)
    {
        return true;
    }

    if (! appendHeaderFmt(header_buf, cap, offset, "Cookie: "))
    {
        return false;
    }

    bool first = true;
    if (ts->split_id_placement == kHttpClientSplitPlacementCookie)
    {
        if (! appendHeaderFmt(header_buf, cap, offset, "%s%s=%s", first ? "" : "; ", ts->split_id_name, ls->split_id))
        {
            return false;
        }
        first = false;
    }
    if (ts->split_direction_placement == kHttpClientSplitPlacementCookie)
    {
        if (! appendHeaderFmt(header_buf, cap, offset, "%s%s=%s", first ? "" : "; ", ts->split_direction_name,
                              direction))
        {
            return false;
        }
        first = false;
    }
    if (ts->split_token != NULL && ts->split_token_placement == kHttpClientSplitPlacementCookie)
    {
        if (! appendHeaderFmt(header_buf, cap, offset, "%s%s=%s", first ? "" : "; ", ts->split_token_name,
                              ts->split_token))
        {
            return false;
        }
    }

    return appendHeaderFmt(header_buf, cap, offset, "\r\n");
}

static line_t *httpclientDownstreamTargetLine(httpclient_lstate_t *ls, line_t *fallback)
{
    if (ls->split_role == kHttpClientSplitRoleDownload && ls->split_main_line != NULL)
    {
        return ls->split_main_line;
    }
    return fallback;
}

static bool httpclientForwardDownstreamPayload(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *buf)
{
    line_t *target = httpclientDownstreamTargetLine(ls, l);
    if (target == NULL || ! lineIsAlive(target))
    {
        lineReuseBuffer(l, buf);
        return false;
    }
    return withLineLockedWithBuf(target, tunnelPrevDownStreamPayload, t, buf);
}

bool httpclientTransportSendHttp1RequestHeaders(tunnel_t *t, line_t *l, bool upgrade_to_h2)
{
    httpclient_tstate_t *ts = tunnelGetState(t);
    httpclient_lstate_t *ls = lineGetState(l, t);
    bool                 split_mode      = (ts->h1_transport_mode == kHttpClientH1TransportSplit) &&
                                           (ls->split_role == kHttpClientSplitRoleUpload ||
                                            ls->split_role == kHttpClientSplitRoleDownload);
    bool                 websocket_mode  = split_mode ? false : ts->websocket_enabled;
    bool                 upgrade_requested = upgrade_to_h2 && ! websocket_mode;
    bool                 custom_upgrade  = upgrade_requested && httpclientUpgradeIsCustom(ts);
    const char          *upgrade_proto   = upgrade_requested ? httpclientUpgradeProtocol(ts) : NULL;
    bool                 request_has_body = ! split_mode || ls->split_role == kHttpClientSplitRoleUpload;
    char                *split_path      = NULL;

    char host_line[512];
    int  host_len = 0;
    if (ts->host_port == 0 || ts->host_port == kHttpClientDefaultHttp1Port || ts->host_port == kHttpClientDefaultHttpsPort)
    {
        host_len = snprintf(host_line, sizeof(host_line), "%s", ts->host);
    }
    else
    {
        host_len = snprintf(host_line, sizeof(host_line), "%s:%d", ts->host, ts->host_port);
    }

    if (host_len <= 0 || (size_t) host_len >= sizeof(host_line))
    {
        LOGE("HttpClient: host header is too large");
        return false;
    }

    char *header_buf = memoryAllocate(kHttpClientMaxHeaderBytes);
    int  offset = 0;

    const char *method = websocket_mode ? "GET" : (split_mode ? httpclientSplitMethod(ts, ls->split_role) : ts->method);
    const char *path   = ts->path;
    if (split_mode)
    {
        split_path = httpclientBuildSplitPath(ts, ls);
        if (split_path == NULL)
        {
            LOGE("HttpClient: failed to build split HTTP/1.1 request path");
            memoryFree(header_buf);
            return false;
        }
        path = split_path;
    }

    if (ts->verbose)
    {
        LOGD("HttpClient: sending HTTP/1.1 request method=%s host=%s path=%s websocket=%s h2c-upgrade=%s", method,
             host_line, path, websocket_mode ? "true" : "false",
             (upgrade_requested && ! custom_upgrade) ? "true" : "false");
    }

    if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "%s %s HTTP/1.1\r\n", method, path) ||
        ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Host: %s\r\n", host_line) ||
        ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "User-Agent: %s\r\n", ts->user_agent) ||
        ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Accept: */*\r\n"))
    {
        LOGE("HttpClient: request headers are too large");
        memoryFree(split_path);
        memoryFree(header_buf);
        return false;
    }

    if (websocket_mode)
    {
        if (! httpclientGenerateWebSocketKey(ls))
        {
            LOGE("HttpClient: failed to generate Sec-WebSocket-Key");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Connection: Upgrade\r\n") ||
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Upgrade: websocket\r\n") ||
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Sec-WebSocket-Version: 13\r\n") ||
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Sec-WebSocket-Key: %s\r\n",
                              ls->websocket_key))
        {
            LOGE("HttpClient: websocket request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (ts->websocket_origin != NULL &&
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Origin: %s\r\n", ts->websocket_origin))
        {
            LOGE("HttpClient: websocket request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (ts->websocket_subprotocol != NULL &&
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Sec-WebSocket-Protocol: %s\r\n",
                              ts->websocket_subprotocol))
        {
            LOGE("HttpClient: websocket request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (ts->websocket_extensions != NULL &&
            ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Sec-WebSocket-Extensions: %s\r\n",
                              ts->websocket_extensions))
        {
            LOGE("HttpClient: websocket request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }
    }
    else if (upgrade_requested)
    {
        if (! custom_upgrade &&
            (ts->upgrade_settings_b64 == NULL || ts->upgrade_settings_payload == NULL || ts->upgrade_settings_payload_len == 0))
        {
            LOGE("HttpClient: HTTP2-Settings is not initialized");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (! custom_upgrade)
        {
            if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset,
                                  "Connection: Upgrade, HTTP2-Settings\r\n") ||
                ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Upgrade: h2c\r\n") ||
                ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "HTTP2-Settings: %s\r\n",
                                  ts->upgrade_settings_b64))
            {
                LOGE("HttpClient: request headers are too large");
                memoryFree(split_path);
                memoryFree(header_buf);
                return false;
            }
        }
        else if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Connection: Upgrade\r\n") ||
                 ! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Upgrade: %s\r\n", upgrade_proto))
        {
            LOGE("HttpClient: request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }

        if (cJSON_IsObject(ts->upgrade_request_headers))
        {
            cJSON *header = NULL;
            cJSON_ArrayForEach(header, ts->upgrade_request_headers)
            {
                if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
                {
                    continue;
                }

                if (httpclientShouldSkipUpgradeExtraHeader(header->string))
                {
                    continue;
                }

                if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                      header->valuestring))
                {
                    LOGE("HttpClient: request headers are too large");
                    memoryFree(split_path);
                    memoryFree(header_buf);
                    return false;
                }
            }
        }
    }
    else
    {
        if (request_has_body)
        {
            if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset,
                                  "Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n"))
            {
                LOGE("HttpClient: request headers are too large");
                memoryFree(split_path);
                memoryFree(header_buf);
                return false;
            }
        }
        else if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset,
                                   "Connection: keep-alive\r\nCache-Control: no-store\r\nPragma: no-cache\r\n"))
        {
            LOGE("HttpClient: request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }
    }

    if (ts->content_type != kContentTypeNone && ts->content_type != kContentTypeUndefined)
    {
        if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "Content-Type: %s\r\n",
                              httpContentTypeStr(ts->content_type)))
        {
            LOGE("HttpClient: request headers are too large");
            memoryFree(split_path);
            memoryFree(header_buf);
            return false;
        }
    }

    if (split_mode && ! httpclientAppendSplitPlacementHeaders(header_buf, kHttpClientMaxHeaderBytes, &offset, ts, ls))
    {
        LOGE("HttpClient: split request headers are too large");
        memoryFree(split_path);
        memoryFree(header_buf);
        return false;
    }

    if (cJSON_IsObject(ts->headers))
    {
        cJSON *header = NULL;
        cJSON_ArrayForEach(header, ts->headers)
        {
            if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
            {
                continue;
            }

            if (httpclientShouldSkipExtraHeader(header->string, upgrade_to_h2, websocket_mode))
            {
                continue;
            }

            if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                  header->valuestring))
            {
                LOGE("HttpClient: request headers are too large");
                memoryFree(split_path);
                memoryFree(header_buf);
                return false;
            }
        }
    }

    const cJSON *side_headers = NULL;
    if (split_mode)
    {
        side_headers = ls->split_role == kHttpClientSplitRoleDownload ? ts->split_download_headers
                                                                      : ts->split_upload_headers;
    }
    if (cJSON_IsObject(side_headers))
    {
        cJSON *header = NULL;
        cJSON_ArrayForEach(header, side_headers)
        {
            if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
            {
                continue;
            }

            if (httpclientShouldSkipExtraHeader(header->string, false, false))
            {
                continue;
            }

            if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                  header->valuestring))
            {
                LOGE("HttpClient: split request headers are too large");
                memoryFree(split_path);
                memoryFree(header_buf);
                return false;
            }
        }
    }

    if (! appendHeaderFmt(header_buf, kHttpClientMaxHeaderBytes, &offset, "\r\n"))
    {
        LOGE("HttpClient: request headers are too large");
        memoryFree(split_path);
        memoryFree(header_buf);
        return false;
    }

    bool ok = sendBytesUp(t, l, header_buf, (uint32_t) offset);
    memoryFree(split_path);
    memoryFree(header_buf);
    return ok;
}

bool httpclientTransportSendHttp1SplitRequestHeaders(tunnel_t *t, line_t *l)
{
    return httpclientTransportSendHttp1RequestHeaders(t, l, false);
}

bool httpclientTransportSendHttp1FinalChunk(tunnel_t *t, line_t *l)
{
    return sendTextUp(t, l, "0\r\n\r\n");
}

bool httpclientTransportSendHttp1ChunkedPayload(tunnel_t *t, line_t *l, sbuf_t *payload)
{
    uint32_t payload_len = sbufGetLength(payload);

    char chunk_prefix[32];
    int  prefix_len = snprintf(chunk_prefix, sizeof(chunk_prefix), "%x\r\n", payload_len);

    if (prefix_len <= 0)
    {
        return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, payload);
    }

    if (sbufGetLeftCapacity(payload) >= (uint32_t) prefix_len)
    {
        sbufShiftLeft(payload, (uint32_t) prefix_len);
        sbufWrite(payload, chunk_prefix, (uint32_t) prefix_len);
    }
    else
    {
        if (! sendBytesUp(t, l, chunk_prefix, (uint32_t) prefix_len))
        {
            lineReuseBuffer(l, payload);
            return false;
        }
    }

    bool     appended_tail = false;
    uint32_t old_len       = sbufGetLength(payload);
    if (sbufGetMaximumWriteableSize(payload) >= old_len + 2)
    {
        sbufSetLength(payload, old_len + 2);
        memoryCopy((uint8_t *) sbufGetMutablePtr(payload) + old_len, "\r\n", 2);
        appended_tail = true;
    }

    if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, payload))
    {
        return false;
    }

    if (! appended_tail)
    {
        if (! sendTextUp(t, l, "\r\n"))
        {
            return false;
        }
    }

    return true;
}

static bool parseHttp1ResponseHeaders(const char *headers, httpclient_h1_response_info_t *info)
{
    if (headers == NULL || info == NULL)
    {
        return false;
    }

    *info = (httpclient_h1_response_info_t){0};

    char *tmp = stringDuplicate(headers);

    char *line_end = strstr(tmp, "\r\n");
    if (line_end == NULL)
    {
        memoryFree(tmp);
        return false;
    }

    *line_end = '\0';

    int status_code = 0;
    if (sscanf(tmp, "HTTP/%*d.%*d %d", &status_code) != 1)
    {
        memoryFree(tmp);
        return false;
    }
    info->status_code = status_code;

    char *line = line_end + 2;
    while (*line != '\0')
    {
        char *next = strstr(line, "\r\n");
        if (next == NULL)
        {
            break;
        }

        *next = '\0';

        if (*line == '\0')
        {
            break;
        }

        char *colon = strchr(line, ':');
        if (colon != NULL)
        {
            *colon = '\0';
            char *key   = line;
            char *value = colon + 1;

            while (*value == ' ' || *value == '\t')
            {
                ++value;
            }

            if (httpclientStringCaseEquals(key, "Transfer-Encoding") && httpclientStringCaseContainsToken(value, "chunked"))
            {
                info->transfer_chunked = true;
            }
            else if (httpclientStringCaseEquals(key, "Connection") && httpclientStringCaseContainsToken(value, "upgrade"))
            {
                info->connection_upgrade = true;
            }
            else if (httpclientStringCaseEquals(key, "Upgrade") && httpclientStringCaseContains(value, "h2c"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
                info->upgrade_h2c = true;
            }
            else if (httpclientStringCaseEquals(key, "Upgrade") && httpclientStringCaseContains(value, "websocket"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
                info->upgrade_websocket = true;
            }
            else if (httpclientStringCaseEquals(key, "Upgrade"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
            }
            else if (httpclientStringCaseEquals(key, "Content-Length"))
            {
                int64_t parsed = 0;
                if (! parseContentLength(value, &parsed))
                {
                    memoryFree(tmp);
                    return false;
                }

                if (! info->has_content_length)
                {
                    info->has_content_length = true;
                    info->content_length     = parsed;
                }
                else if (info->content_length != parsed)
                {
                    memoryFree(tmp);
                    return false;
                }
            }
            else if (httpclientStringCaseEquals(key, "Sec-WebSocket-Accept"))
            {
                info->has_sec_websocket_accept = true;
                snprintf(info->sec_websocket_accept, sizeof(info->sec_websocket_accept), "%s", value);
            }
            else if (httpclientStringCaseEquals(key, "Sec-WebSocket-Protocol"))
            {
                info->has_sec_websocket_protocol = true;
                snprintf(info->sec_websocket_protocol, sizeof(info->sec_websocket_protocol), "%s", value);
            }
            else if (httpclientStringCaseEquals(key, "Sec-WebSocket-Extensions"))
            {
                info->has_sec_websocket_extensions = true;
                snprintf(info->sec_websocket_extensions, sizeof(info->sec_websocket_extensions), "%s", value);
            }
        }

        line = next + 2;
    }

    memoryFree(tmp);
    return true;
}

static bool sendNghttp2Outbound(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    buffer_pool_t *pool      = lineGetBufferPool(l);
    uint32_t       max_chunk = bufferpoolGetLargeBufferSize(pool);
    if (max_chunk == 0)
    {
        return false;
    }

    while (true)
    {
        const uint8_t *data = NULL;
        nghttp2_ssize   len  = nghttp2_session_mem_send2(ls->session, &data);

        if (len < 0)
        {
            LOGE("HttpClient: nghttp2_session_mem_send2 failed");
            return false;
        }

        if (len == 0)
        {
            break;
        }

        if ((uint64_t) len > UINT32_MAX)
        {
            LOGE("HttpClient: outgoing HTTP/2 frame exceeds buffer limits");
            return false;
        }

        uint32_t        rem = (uint32_t) len;
        const uint8_t  *ptr = data;
        while (rem > 0)
        {
            uint32_t chunk = min(rem, max_chunk);
            sbuf_t  *buf   = allocBufferForLength(l, chunk);

            sbufSetLength(buf, chunk);
            sbufWriteLarge(buf, ptr, chunk);

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, buf))
            {
                return false;
            }

            ptr += chunk;
            rem -= chunk;
        }
    }

    return true;
}

static int httpclientOnHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                      size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                                      void *userdata)
{
    discard session;
    discard flags;

    if (userdata == NULL || frame == NULL || name == NULL || value == NULL)
    {
        return 0;
    }

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;
    httpclient_tstate_t *ts = tunnelGetState(ls->tunnel);

    if (! ts->websocket_enabled || frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
    {
        return 0;
    }

    if (ls->h2_stream_id != 0 && frame->hd.stream_id != ls->h2_stream_id)
    {
        return 0;
    }

    if (namelen == 7 && memoryCompare(name, ":status", 7) == 0)
    {
        char status_buf[8];
        size_t copy_len = min(valuelen, sizeof(status_buf) - 1U);
        memoryCopy(status_buf, value, copy_len);
        status_buf[copy_len]        = '\0';
        ls->websocket_h2_status_code = atoi(status_buf);
        ls->websocket_h2_status_seen = true;
        return 0;
    }

    if (namelen == 22 && memoryCompare(name, "sec-websocket-protocol", 22) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_protocol) - 1U);
        memoryCopy(ls->websocket_h2_protocol, value, copy_len);
        ls->websocket_h2_protocol[copy_len] = '\0';
        ls->websocket_h2_protocol_seen      = true;
        return 0;
    }

    if (namelen == 24 && memoryCompare(name, "sec-websocket-extensions", 24) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_extensions) - 1U);
        memoryCopy(ls->websocket_h2_extensions, value, copy_len);
        ls->websocket_h2_extensions[copy_len] = '\0';
        ls->websocket_h2_extensions_seen      = true;
    }

    return 0;
}

static int httpclientOnDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                             const uint8_t *data, size_t len, void *userdata)
{
    discard session;
    discard flags;

    if (userdata == NULL || len == 0)
    {
        return 0;
    }

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;

    if (ls->h2_stream_id != 0 && stream_id != ls->h2_stream_id)
    {
        return 0;
    }

    buffer_pool_t *pool      = lineGetBufferPool(ls->line);
    uint32_t       max_chunk = bufferpoolGetLargeBufferSize(pool);
    if (max_chunk == 0)
    {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    uint32_t       rem = (uint32_t) len;
    const uint8_t *ptr = data;
    while (rem > 0)
    {
        uint32_t chunk = min(rem, max_chunk);
        sbuf_t  *buf   = allocBufferForLength(ls->line, chunk);
        sbufSetLength(buf, chunk);
        sbufWriteLarge(buf, ptr, chunk);

        httpclient_tstate_t *ts = tunnelGetState(ls->tunnel);
        if (ts->websocket_enabled)
        {
            bufferstreamPush(&ls->in_stream, buf);
        }
        else
        {
            contextqueuePush(&ls->events_down, contextCreatePayload(ls->line, buf));
        }
        ptr += chunk;
        rem -= chunk;
    }

    return 0;
}

static int httpclientOnFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    discard session;

    if (userdata == NULL)
    {
        return 0;
    }

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;

    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
    {
        if (ls->h2_stream_id == 0)
        {
            ls->h2_stream_id = frame->hd.stream_id;
        }

        if (frame->hd.stream_id == ls->h2_stream_id)
        {
            ls->h2_headers_received = true;
            httpclient_tstate_t *ts = tunnelGetState(ls->tunnel);
            if (ts->websocket_enabled)
            {
                bool protocol_ok = true;
                if (ts->websocket_subprotocol != NULL)
                {
                    protocol_ok = ls->websocket_h2_protocol_seen &&
                                  httpclientStringCaseEquals(ls->websocket_h2_protocol, ts->websocket_subprotocol);
                }
                else if (ls->websocket_h2_protocol_seen)
                {
                    protocol_ok = false;
                }

                ls->websocket_active =
                    ls->websocket_h2_status_seen && ls->websocket_h2_status_code == 200 && protocol_ok;
            }
        }
    }

    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == NGHTTP2_FLAG_END_STREAM && frame->hd.stream_id == ls->h2_stream_id)
    {
        ls->response_complete = true;
    }

    return 0;
}

static int httpclientOnStreamClosedCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                            void *userdata)
{
    discard session;
    discard error_code;

    if (userdata == NULL)
    {
        return 0;
    }

    httpclient_lstate_t *ls = (httpclient_lstate_t *) userdata;

    if (stream_id == ls->h2_stream_id)
    {
        ls->response_complete = true;
    }

    return 0;
}

static bool httpclientSubmitHttp2RequestHeaders(httpclient_tstate_t *ts, httpclient_lstate_t *ls, int32_t *stream_id_out)
{
    if (ts == NULL || ls == NULL || stream_id_out == NULL)
    {
        return false;
    }

    char authority[512];
    int  authority_len = 0;
    if (ts->host_port == 0 || ts->host_port == kHttpClientDefaultHttp1Port || ts->host_port == kHttpClientDefaultHttpsPort)
    {
        authority_len = snprintf(authority, sizeof(authority), "%s", ts->host);
    }
    else
    {
        authority_len = snprintf(authority, sizeof(authority), "%s:%d", ts->host, ts->host_port);
    }

    if (authority_len <= 0 || (size_t) authority_len >= sizeof(authority))
    {
        LOGE("HttpClient: authority header is too large");
        return false;
    }

    nghttp2_nv nvs[20];
    int        nvlen = 0;

    if (ts->websocket_enabled)
    {
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":method",
                                     .value = (uint8_t *) "CONNECT",
                                     .namelen = 7,
                                     .valuelen = 7,
                                     .flags = NGHTTP2_NV_FLAG_NONE};
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":protocol",
                                     .value = (uint8_t *) "websocket",
                                     .namelen = 9,
                                     .valuelen = 9,
                                     .flags = NGHTTP2_NV_FLAG_NONE};
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":scheme",
                                     .value = (uint8_t *) ts->scheme,
                                     .namelen = 7,
                                     .valuelen = stringLength(ts->scheme),
                                     .flags = NGHTTP2_NV_FLAG_NONE};
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":path",
                                     .value = (uint8_t *) ts->path,
                                     .namelen = 5,
                                     .valuelen = stringLength(ts->path),
                                     .flags = NGHTTP2_NV_FLAG_NONE};
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":authority",
                                     .value = (uint8_t *) authority,
                                     .namelen = 10,
                                     .valuelen = stringLength(authority),
                                     .flags = NGHTTP2_NV_FLAG_NONE};
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "sec-websocket-version",
                                     .value = (uint8_t *) "13",
                                     .namelen = 21,
                                     .valuelen = 2,
                                     .flags = NGHTTP2_NV_FLAG_NONE};

        if (ts->user_agent != NULL)
        {
            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "user-agent",
                                         .value = (uint8_t *) ts->user_agent,
                                         .namelen = 10,
                                         .valuelen = stringLength(ts->user_agent),
                                         .flags = NGHTTP2_NV_FLAG_NONE};
        }

        if (ts->websocket_origin != NULL)
        {
            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "origin",
                                         .value = (uint8_t *) ts->websocket_origin,
                                         .namelen = 6,
                                         .valuelen = stringLength(ts->websocket_origin),
                                         .flags = NGHTTP2_NV_FLAG_NONE};
        }

        if (ts->websocket_subprotocol != NULL)
        {
            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "sec-websocket-protocol",
                                         .value = (uint8_t *) ts->websocket_subprotocol,
                                         .namelen = 22,
                                         .valuelen = stringLength(ts->websocket_subprotocol),
                                         .flags = NGHTTP2_NV_FLAG_NONE};
        }

        if (ts->websocket_extensions != NULL)
        {
            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "sec-websocket-extensions",
                                         .value = (uint8_t *) ts->websocket_extensions,
                                         .namelen = 24,
                                         .valuelen = stringLength(ts->websocket_extensions),
                                         .flags = NGHTTP2_NV_FLAG_NONE};
        }
    }
    else
    {
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":method",
                                     .value = (uint8_t *) ts->method,
                                     .namelen = 7,
                                     .valuelen = stringLength(ts->method),
                                     .flags = NGHTTP2_NV_FLAG_NONE};

        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":path",
                                     .value = (uint8_t *) ts->path,
                                     .namelen = 5,
                                     .valuelen = stringLength(ts->path),
                                     .flags = NGHTTP2_NV_FLAG_NONE};

        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":scheme",
                                     .value = (uint8_t *) ts->scheme,
                                     .namelen = 7,
                                     .valuelen = stringLength(ts->scheme),
                                     .flags = NGHTTP2_NV_FLAG_NONE};

        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":authority",
                                     .value = (uint8_t *) authority,
                                     .namelen = 10,
                                     .valuelen = stringLength(authority),
                                     .flags = NGHTTP2_NV_FLAG_NONE};

        if (ts->user_agent != NULL)
        {
            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "user-agent",
                                         .value = (uint8_t *) ts->user_agent,
                                         .namelen = 10,
                                         .valuelen = stringLength(ts->user_agent),
                                         .flags = NGHTTP2_NV_FLAG_NONE};
        }

        if (ts->content_type != kContentTypeNone && ts->content_type != kContentTypeUndefined)
        {
            const char *ctype = httpContentTypeStr(ts->content_type);
            nvs[nvlen++]      = (nghttp2_nv) {.name = (uint8_t *) "content-type",
                                              .value = (uint8_t *) ctype,
                                              .namelen = 12,
                                              .valuelen = stringLength(ctype),
                                              .flags = NGHTTP2_NV_FLAG_NONE};
        }
    }

    if (cJSON_IsObject(ts->headers))
    {
        cJSON *header = NULL;
        cJSON_ArrayForEach(header, ts->headers)
        {
            if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
            {
                continue;
            }

            if (header->string[0] == ':' ||
                httpclientShouldSkipExtraHeader(header->string, false, ts->websocket_enabled))
            {
                continue;
            }

            if (nvlen >= (int) ARRAY_SIZE(nvs))
            {
                break;
            }

            nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) header->string,
                                          .value = (uint8_t *) header->valuestring,
                                          .namelen = stringLength(header->string),
                                          .valuelen = stringLength(header->valuestring),
                                          .flags = NGHTTP2_NV_FLAG_NONE};
        }
    }

    int32_t stream_id = nghttp2_submit_headers(ls->session, NGHTTP2_FLAG_END_HEADERS, -1, NULL, nvs, (size_t) nvlen, NULL);
    if (stream_id <= 0)
    {
        LOGE("HttpClient: nghttp2_submit_headers failed");
        return false;
    }

    *stream_id_out = stream_id;
    return true;
}

static bool httpclientTransportMaybeSubmitWebSocketHttp2Request(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (! ts->websocket_enabled || ls->session == NULL || ls->websocket_h2_request_submitted)
    {
        return true;
    }

    if (nghttp2_session_get_remote_settings(ls->session, NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL) != 1)
    {
        return true;
    }

    int32_t stream_id = 0;
    if (! httpclientSubmitHttp2RequestHeaders(ts, ls, &stream_id))
    {
        return false;
    }

    ls->h2_stream_id                    = stream_id;
    ls->websocket_h2_request_submitted  = true;
    ls->websocket_h2_waiting_connect    = false;
    ls->websocket_waiting_handshake     = true;
    ls->runtime_proto                   = kHttpClientRuntimeHttp2;

    if (ts->verbose)
    {
        LOGD("HttpClient: submitted websocket HTTP/2 extended CONNECT stream_id=%d authority=%s path=%s", stream_id,
             ts->host, ts->path);
    }

    return sendNghttp2Outbound(t, l, ls);
}

bool httpclientTransportEnsureHttp2Session(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (ls->session != NULL)
    {
        return httpclientTransportMaybeSubmitWebSocketHttp2Request(t, l, ls);
    }

    httpclient_tstate_t *ts = tunnelGetState(t);

    nghttp2_session_callbacks_set_on_header_callback(ts->cbs, httpclientOnHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ts->cbs, httpclientOnDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(ts->cbs, httpclientOnFrameRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(ts->cbs, httpclientOnStreamClosedCallback);

    if (nghttp2_session_client_new3(&ls->session, ts->cbs, ls, ts->ngoptions, NULL) != 0)
    {
        LOGE("HttpClient: nghttp2_session_client_new3 failed");
        return false;
    }

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 20)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (uint32_t) kHttpClientHttp2FrameBytes},
        {NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, ts->websocket_enabled ? 1U : 0U}
    };

    if (nghttp2_submit_settings(ls->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings)) != 0)
    {
        LOGE("HttpClient: nghttp2_submit_settings failed");
        return false;
    }

    ls->runtime_proto = kHttpClientRuntimeHttp2;

    if (ts->websocket_enabled)
    {
        ls->websocket_h2_waiting_connect = true;
        if (ts->verbose)
        {
            LOGD("HttpClient: HTTP/2 session ready, waiting for peer SETTINGS_ENABLE_CONNECT_PROTOCOL before websocket CONNECT");
        }
        return sendNghttp2Outbound(t, l, ls);
    }

    int32_t stream_id = 0;
    if (! httpclientSubmitHttp2RequestHeaders(ts, ls, &stream_id))
    {
        return false;
    }

    ls->h2_stream_id = stream_id;
    if (ts->verbose)
    {
        LOGD("HttpClient: submitted HTTP/2 request stream_id=%d method=%s path=%s", stream_id, ts->method, ts->path);
    }
    return sendNghttp2Outbound(t, l, ls);
}

bool httpclientTransportHandleUpgradeAccepted(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ts->upgrade_settings_payload == NULL || ts->upgrade_settings_payload_len == 0)
    {
        LOGE("HttpClient: upgrade settings payload is missing");
        return false;
    }

    if (ls->session == NULL)
    {
        nghttp2_session_callbacks_set_on_header_callback(ts->cbs, httpclientOnHeaderCallback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ts->cbs, httpclientOnDataChunkRecvCallback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(ts->cbs, httpclientOnFrameRecvCallback);
        nghttp2_session_callbacks_set_on_stream_close_callback(ts->cbs, httpclientOnStreamClosedCallback);

        if (nghttp2_session_client_new3(&ls->session, ts->cbs, ls, ts->ngoptions, NULL) != 0)
        {
            LOGE("HttpClient: nghttp2_session_client_new3 failed");
            return false;
        }
    }

    int head_request = (ts->method_enum == kHttpHead) ? 1 : 0;
    if (nghttp2_session_upgrade2(ls->session, ts->upgrade_settings_payload, ts->upgrade_settings_payload_len, head_request,
                                 ls) != 0)
    {
        LOGE("HttpClient: nghttp2_session_upgrade2 failed");
        return false;
    }

    ls->h2_stream_id  = 1;
    ls->runtime_proto = kHttpClientRuntimeHttp2;

    if (ts->verbose)
    {
        LOGD("HttpClient: accepted h2c upgrade and switched to HTTP/2 stream_id=1");
    }

    return sendNghttp2Outbound(t, l, ls);
}

static bool httpclientTransportHandleCustomUpgradeAccepted(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclient_tstate_t *ts = tunnelGetState(t);

    ls->runtime_proto = kHttpClientRuntimeUpgradedRaw;

    if (ts->verbose)
    {
        LOGD("HttpClient: accepted HTTP/1.1 custom upgrade protocol=%s", httpclientUpgradeProtocol(ts));
    }

    discard t;
    discard l;
    return true;
}

bool httpclientTransportSendWebSocketData(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *payload,
                                          uint8_t opcode)
{
    if (payload == NULL)
    {
        return true;
    }

    uint32_t payload_len = sbufGetLength(payload);
    uint8_t  header[16];
    uint8_t  mask_key[4] = {0};
    getRandomBytes(mask_key, sizeof(mask_key));

    size_t header_len =
        httpclientBuildWebSocketHeader(header, sizeof(header), opcode, payload_len, true, mask_key);
    if (header_len == 0)
    {
        lineReuseBuffer(l, payload);
        return false;
    }

    httpclientMaskWebSocketPayload(payload, mask_key);

    if (sbufGetLeftCapacity(payload) >= header_len)
    {
        sbufShiftLeft(payload, (uint32_t) header_len);
        sbufWrite(payload, header, (uint32_t) header_len);
        return httpclientSendRawUp(t, l, ls, payload);
    }

    if (! httpclientSendRawBytesUp(t, l, ls, header, (uint32_t) header_len))
    {
        lineReuseBuffer(l, payload);
        return false;
    }

    return httpclientSendRawUp(t, l, ls, payload);
}

bool httpclientTransportSendWebSocketClose(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (ls->websocket_close_sent)
    {
        return true;
    }

    ls->websocket_close_sent = true;
    if (httpclientVerboseEnabled(t))
    {
        LOGD("HttpClient: sending websocket close frame");
    }
    return httpclientSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodeClose, NULL, 0);
}

bool httpclientTransportDrainWebSocketDown(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    while (true)
    {
        size_t available = bufferstreamGetBufLen(&ls->in_stream);
        if (available < 2)
        {
            return true;
        }

        uint8_t head[14];
        bufferstreamViewBytesAt(&ls->in_stream, 0, head, 2);

        bool   fin         = (head[0] & 0x80U) != 0;
        uint8_t opcode      = (uint8_t) (head[0] & 0x0FU);
        bool   masked      = (head[1] & 0x80U) != 0;
        uint64_t payload_len = (uint64_t) (head[1] & 0x7FU);
        size_t header_len    = 2;

        if (masked)
        {
            LOGE("HttpClient: server websocket frames must not be masked opcode=%s payload_len=%" PRIu64,
                 httpclientWebSocketOpcodeName(opcode), payload_len);
            return false;
        }

        if (payload_len == 126U)
        {
            if (available < 4)
            {
                return true;
            }
            bufferstreamViewBytesAt(&ls->in_stream, 2, head + 2, 2);
            payload_len = ((uint64_t) head[2] << 8) | (uint64_t) head[3];
            header_len  = 4;
        }
        else if (payload_len == 127U)
        {
            if (available < 10)
            {
                return true;
            }
            bufferstreamViewBytesAt(&ls->in_stream, 2, head + 2, 8);
            payload_len = 0;
            for (size_t i = 0; i < 8; ++i)
            {
                payload_len = (payload_len << 8) | (uint64_t) head[2 + i];
            }
            header_len = 10;
        }

        if ((opcode & 0x08U) != 0 && (! fin || payload_len > 125U))
        {
            LOGE("HttpClient: invalid websocket control frame opcode=%s fin=%s payload_len=%" PRIu64,
                 httpclientWebSocketOpcodeName(opcode), fin ? "true" : "false", payload_len);
            return false;
        }

        if (payload_len > UINT32_MAX)
        {
            LOGE("HttpClient: websocket frame exceeds buffer limits opcode=%s payload_len=%" PRIu64,
                 httpclientWebSocketOpcodeName(opcode), payload_len);
            return false;
        }

        if (available < header_len + (size_t) payload_len)
        {
            return true;
        }

        sbuf_t *discard_header = bufferstreamReadExact(&ls->in_stream, header_len);
        lineReuseBuffer(l, discard_header);

        sbuf_t *payload = NULL;
        if (payload_len > 0)
        {
            payload = bufferstreamReadExact(&ls->in_stream, (size_t) payload_len);
        }

        if (opcode == kWebSocketOpcodePing)
        {
            if (httpclientVerboseEnabled(t))
            {
                LOGD("HttpClient: received websocket ping payload_len=%u", payload == NULL ? 0U : sbufGetLength(payload));
            }
            const void *pong_data = (payload == NULL) ? NULL : sbufGetRawPtr(payload);
            uint32_t    pong_len  = (payload == NULL) ? 0U : sbufGetLength(payload);
            bool        ok        = httpclientSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodePong, pong_data,
                                                                        pong_len);
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            if (! ok)
            {
                return false;
            }
            continue;
        }

        if (opcode == kWebSocketOpcodePong)
        {
            if (httpclientVerboseEnabled(t))
            {
                LOGD("HttpClient: received websocket pong payload_len=%u", payload == NULL ? 0U : sbufGetLength(payload));
            }
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            continue;
        }

        if (opcode == kWebSocketOpcodeClose)
        {
            if (httpclientVerboseEnabled(t))
            {
                LOGD("HttpClient: received websocket close payload_len=%u close_sent=%s",
                     payload == NULL ? 0U : sbufGetLength(payload), ls->websocket_close_sent ? "true" : "false");
            }

            if (! ls->websocket_close_sent)
            {
                const void *close_data = (payload == NULL) ? NULL : sbufGetRawPtr(payload);
                uint32_t    close_len  = (payload == NULL) ? 0U : sbufGetLength(payload);
                if (! httpclientSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodeClose, close_data, close_len))
                {
                    if (payload != NULL)
                    {
                        lineReuseBuffer(l, payload);
                    }
                    LOGE("HttpClient: failed to send websocket close reply");
                    return false;
                }
                ls->websocket_close_sent = true;
            }

            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            ls->websocket_close_received = true;
            return true;
        }

        if (opcode != kWebSocketOpcodeBinary && opcode != kWebSocketOpcodeText &&
            opcode != kWebSocketOpcodeContinuation)
        {
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            LOGE("HttpClient: unsupported websocket opcode=%u", opcode);
            return false;
        }

        if (payload != NULL && ! httpclientForwardDownstreamPayload(t, l, ls, payload))
        {
            return false;
        }
    }
}

static void httpclientTransportCloseDirections(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, bool close_next,
                                               bool close_prev)
{
    lineLock(l);

    bool send_next = close_next && ! ls->next_finished;
    bool send_prev = close_prev && ! ls->prev_finished;

    ls->next_finished     = true;
    ls->prev_finished     = true;
    ls->response_complete = true;

    httpclientLinestateDestroy(ls);

    if (send_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (lineIsAlive(l) && send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

void httpclientTransportCloseBothDirections(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclientTransportCloseDirections(t, l, ls, true, true);
}

void httpclientTransportCloseNextDirection(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclientTransportCloseDirections(t, l, ls, true, false);
}

bool httpclientTransportSendHttp2DataFrame(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *payload,
                                           bool end_stream)
{
    if (ls->h2_stream_id <= 0)
    {
        if (payload != NULL)
        {
            bufferqueuePushBack(&ls->pending_up, payload);
        }
        return true;
    }

    uint32_t payload_len = (payload == NULL) ? 0 : sbufGetLength(payload);

    if (httpclientVerboseEnabled(t))
    {
        LOGD("HttpClient: sending HTTP/2 DATA stream_id=%d payload_len=%u end_stream=%s", ls->h2_stream_id,
             payload_len, end_stream ? "true" : "false");
    }

    if (payload_len == 0 && payload != NULL && ! end_stream)
    {
        lineReuseBuffer(l, payload);
        return true;
    }

    uint32_t remote_max = nghttp2_session_get_remote_settings(ls->session, NGHTTP2_SETTINGS_MAX_FRAME_SIZE);
    if (remote_max < HTTP2_FRAME_HDLEN)
    {
        remote_max = (1U << 14);
    }

    buffer_pool_t *pool           = lineGetBufferPool(l);
    uint32_t       large_buf_size = bufferpoolGetLargeBufferSize(pool);
    if (large_buf_size == 0)
    {
        if (payload != NULL)
        {
            lineReuseBuffer(l, payload);
        }
        return false;
    }

    uint32_t frame_limit = min((uint32_t) kHttpClientHttp2FrameBytes, remote_max);
    if (frame_limit < (1U << 14))
    {
        frame_limit = (1U << 14);
    }

    bool send_empty_frame = (payload == NULL) || (payload_len == 0 && end_stream);

    if (! send_empty_frame && payload_len <= frame_limit)
    {
        http2_frame_hd frame = {.length    = payload_len,
                                .type      = kHttP2Data,
                                .flags     = end_stream ? kHttP2FlagEndStream : kHttP2FlagNone,
                                .stream_id = (unsigned int) ls->h2_stream_id};

        if (sbufGetLeftCapacity(payload) >= HTTP2_FRAME_HDLEN)
        {
            sbufShiftLeft(payload, HTTP2_FRAME_HDLEN);
            http2FrameHdPack(&frame, sbufGetMutablePtr(payload));
            return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, payload);
        }

        sbuf_t *header_buf = allocBufferForLength(l, HTTP2_FRAME_HDLEN);
        sbufSetLength(header_buf, HTTP2_FRAME_HDLEN);
        http2FrameHdPack(&frame, sbufGetMutablePtr(header_buf));

        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, header_buf))
        {
            lineReuseBuffer(l, payload);
            return false;
        }

        return withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, payload);
    }

    uint32_t       remaining   = payload_len;
    const uint8_t *payload_ptr = (payload == NULL) ? NULL : (const uint8_t *) sbufGetRawPtr(payload);

    while (remaining > 0 || send_empty_frame)
    {
        uint32_t frame_payload = send_empty_frame ? 0 : min(remaining, min(frame_limit, large_buf_size));
        bool     frame_end     = end_stream && (send_empty_frame || remaining == frame_payload);

        http2_frame_hd frame = {.length    = frame_payload,
                                .type      = kHttP2Data,
                                .flags     = frame_end ? kHttP2FlagEndStream : kHttP2FlagNone,
                                .stream_id = (unsigned int) ls->h2_stream_id};

        sbuf_t *header_buf = allocBufferForLength(l, HTTP2_FRAME_HDLEN);
        sbufSetLength(header_buf, HTTP2_FRAME_HDLEN);
        http2FrameHdPack(&frame, sbufGetMutablePtr(header_buf));
        if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, header_buf))
        {
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            return false;
        }

        if (frame_payload > 0)
        {
            sbuf_t *data_buf = allocBufferForLength(l, frame_payload);
            sbufSetLength(data_buf, frame_payload);
            sbufWriteLarge(data_buf, payload_ptr, frame_payload);
            payload_ptr += frame_payload;
            remaining -= frame_payload;

            if (! withLineLockedWithBuf(l, tunnelNextUpStreamPayload, t, data_buf))
            {
                if (payload != NULL)
                {
                    lineReuseBuffer(l, payload);
                }
                return false;
            }
        }

        if (send_empty_frame)
        {
            break;
        }
    }

    if (payload != NULL)
    {
        lineReuseBuffer(l, payload);
    }

    return true;
}

bool httpclientTransportFlushPendingUp(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    httpclient_tstate_t *ts = tunnelGetState(t);

    if (ts->websocket_enabled && ! ls->websocket_active)
    {
        return true;
    }

    while (bufferqueueGetBufCount(&ls->pending_up) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);

        if (ts->websocket_enabled)
        {
            if (! httpclientTransportSendWebSocketData(t, l, ls, buf, kWebSocketOpcodeBinary))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpClientRuntimeUpgradedRaw)
        {
            tunnelNextUpStreamPayload(t, l, buf);

            if (! lineIsAlive(l))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpClientRuntimeHttp2)
        {
            if (! httpclientTransportSendHttp2DataFrame(t, l, ls, buf, false))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpClientRuntimeHttp1)
        {
            if (! httpclientTransportSendHttp1ChunkedPayload(t, l, buf))
            {
                return false;
            }
        }
        else
        {
            bufferqueuePushFront(&ls->pending_up, buf);
            return true;
        }
    }

    return true;
}

static bool httpclientTransportDrainRawDown(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *buf = bufferstreamIdealRead(&ls->in_stream);

        if (ls->prev_finished)
        {
            lineReuseBuffer(l, buf);
            continue;
        }

        if (! httpclientForwardDownstreamPayload(t, l, ls, buf))
        {
            return false;
        }
    }

    return true;
}

static bool drainDownEvents(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    while (contextqueueLen(&ls->events_down) > 0)
    {
        context_t *ctx = contextqueuePop(&ls->events_down);

        lineLock(l);
        contextApplyOnPrevTunnelD(ctx, t);
        contextDestroy(ctx);

        if (! lineIsAlive(l))
        {
            lineUnlock(l);
            return false;
        }
        lineUnlock(l);
    }

    return true;
}

bool httpclientTransportFeedHttp2Input(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *buf)
{
    uint32_t       len = sbufGetLength(buf);
    const uint8_t *ptr = (const uint8_t *) sbufGetRawPtr(buf);

    while (len > 0)
    {
        nghttp2_ssize ret = nghttp2_session_mem_recv2(ls->session, ptr, len);
        if (ret < 0)
        {
            LOGE("HttpClient: nghttp2_session_mem_recv2 failed (%zd)", ret);
            lineReuseBuffer(l, buf);
            return false;
        }

        if (ret == 0)
        {
            LOGE("HttpClient: nghttp2_session_mem_recv2 consumed 0 bytes");
            lineReuseBuffer(l, buf);
            return false;
        }

        ptr += (size_t) ret;
        len -= (uint32_t) ret;
    }

    lineReuseBuffer(l, buf);

    if (! httpclientTransportMaybeSubmitWebSocketHttp2Request(t, l, ls))
    {
        return false;
    }

    if (! sendNghttp2Outbound(t, l, ls))
    {
        return false;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->websocket_enabled)
    {
        if (! drainDownEvents(t, l, ls))
        {
            return false;
        }
    }

    if (ts->websocket_enabled && ls->websocket_h2_request_submitted && ls->h2_headers_received && ! ls->websocket_active)
    {
        LOGE("HttpClient: websocket HTTP/2 handshake failed status_seen=%s status=%d protocol_seen=%s protocol=%s extensions_seen=%s extensions=%s",
             ls->websocket_h2_status_seen ? "true" : "false", ls->websocket_h2_status_code,
             ls->websocket_h2_protocol_seen ? "true" : "false",
             ls->websocket_h2_protocol_seen ? ls->websocket_h2_protocol : "<none>",
             ls->websocket_h2_extensions_seen ? "true" : "false",
             ls->websocket_h2_extensions_seen ? ls->websocket_h2_extensions : "<none>");
        return false;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        ls->websocket_waiting_handshake = false;
        if (ts->verbose)
        {
            LOGD("HttpClient: websocket HTTP/2 handshake accepted stream_id=%d protocol=%s", ls->h2_stream_id,
                 ls->websocket_h2_protocol_seen ? ls->websocket_h2_protocol : "<none>");
        }
        if (! httpclientTransportDrainWebSocketDown(t, l, ls))
        {
            return false;
        }
        if (! httpclientTransportFlushPendingUp(t, l, ls))
        {
            return false;
        }
    }

    return true;
}

bool httpclientTransportHandleHttp1ResponseHeaderPhase(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    while (! ls->h1_headers_parsed)
    {
        if (bufferstreamGetBufLen(&ls->in_stream) > kHttpClientMaxHeaderBytes)
        {
            LOGE("HttpClient: response header exceeded maximum size");
            return false;
        }

        size_t header_end = 0;
        if (! bufferstreamFindDoubleCRLF(&ls->in_stream, &header_end))
        {
            return true;
        }

        sbuf_t *header_buf = bufferstreamReadExact(&ls->in_stream, header_end);

        char *header_text = memoryAllocate(header_end + 1);
        memoryCopy(header_text, sbufGetRawPtr(header_buf), header_end);
        header_text[header_end] = '\0';

        httpclient_h1_response_info_t info;
        bool                          parsed_ok = parseHttp1ResponseHeaders(header_text, &info);

        lineReuseBuffer(l, header_buf);

        if (! parsed_ok)
        {
            memoryFree(header_text);
            LOGE("HttpClient: invalid HTTP/1.1 response headers");
            return false;
        }

        httpclient_tstate_t *ts = tunnelGetState(t);
        if (ts->websocket_enabled)
        {
            if (ts->verbose)
            {
                LOGD("HttpClient: parsed websocket HTTP/1.1 response status=%d connection-upgrade=%s upgrade-websocket=%s accept=%s protocol=%s extensions=%s",
                     info.status_code, info.connection_upgrade ? "true" : "false",
                     info.upgrade_websocket ? "true" : "false",
                     info.has_sec_websocket_accept ? info.sec_websocket_accept : "<none>",
                     info.has_sec_websocket_protocol ? info.sec_websocket_protocol : "<none>",
                     info.has_sec_websocket_extensions ? info.sec_websocket_extensions : "<none>");
            }

            if (info.status_code != 101 || ! info.connection_upgrade || ! info.upgrade_websocket ||
                ! info.has_sec_websocket_accept)
            {
                LOGE("HttpClient: websocket HTTP/1.1 handshake was rejected status=%d connection-upgrade=%s upgrade-websocket=%s accept=%s",
                     info.status_code, info.connection_upgrade ? "true" : "false",
                     info.upgrade_websocket ? "true" : "false",
                     info.has_sec_websocket_accept ? "true" : "false");
                memoryFree(header_text);
                return false;
            }

            char expected_accept[128];
            httpclientBuildWebSocketAccept(ls->websocket_key, expected_accept, sizeof(expected_accept));
            if (expected_accept[0] == '\0' ||
                ! httpclientStringCaseEquals(expected_accept, info.sec_websocket_accept))
            {
                LOGE("HttpClient: websocket Sec-WebSocket-Accept validation failed expected=%s got=%s", expected_accept,
                     info.has_sec_websocket_accept ? info.sec_websocket_accept : "<none>");
                memoryFree(header_text);
                return false;
            }

            if (ts->websocket_subprotocol != NULL)
            {
                if (! info.has_sec_websocket_protocol ||
                    ! httpclientStringCaseEquals(info.sec_websocket_protocol, ts->websocket_subprotocol))
                {
                    LOGE("HttpClient: websocket subprotocol negotiation failed expected=%s got=%s",
                         ts->websocket_subprotocol,
                         info.has_sec_websocket_protocol ? info.sec_websocket_protocol : "<none>");
                    memoryFree(header_text);
                    return false;
                }
            }
            else if (info.has_sec_websocket_protocol)
            {
                LOGE("HttpClient: websocket server selected an unexpected subprotocol=%s", info.sec_websocket_protocol);
                memoryFree(header_text);
                return false;
            }

            if (info.has_sec_websocket_extensions)
            {
                LOGE("HttpClient: websocket server selected unsupported extensions=%s",
                     info.sec_websocket_extensions);
                memoryFree(header_text);
                return false;
            }

            ls->runtime_proto             = kHttpClientRuntimeHttp1;
            ls->h1_headers_parsed         = true;
            ls->websocket_active          = true;
            ls->websocket_waiting_handshake = false;

            if (ts->verbose)
            {
                LOGD("HttpClient: websocket HTTP/1.1 handshake accepted protocol=%s",
                     info.has_sec_websocket_protocol ? info.sec_websocket_protocol : "<none>");
            }

            if (! httpclientTransportFlushPendingUp(t, l, ls))
            {
                memoryFree(header_text);
                return false;
            }

            memoryFree(header_text);
            return httpclientTransportDrainWebSocketDown(t, l, ls);
        }

        if (info.status_code == 101)
        {
            if (ls->runtime_proto == kHttpClientRuntimeWaitUpgrade && info.connection_upgrade &&
                httpclientUpgradeIsCustom(ts) && info.has_upgrade_header &&
                httpclientStringCaseContainsToken(info.upgrade_value, httpclientUpgradeProtocol(ts)) &&
                httpclientValidateRequiredHeaders(header_text, ts->upgrade_response_headers))
            {
                ls->h1_headers_parsed = true;

                if (! httpclientTransportHandleCustomUpgradeAccepted(t, l, ls))
                {
                    memoryFree(header_text);
                    return false;
                }

                memoryFree(header_text);

                if (! httpclientTransportDrainRawDown(t, l, ls))
                {
                    return lineIsAlive(l) ? false : true;
                }

                if (! httpclientTransportFlushPendingUp(t, l, ls))
                {
                    return lineIsAlive(l) ? false : true;
                }

                return true;
            }

            if (ls->runtime_proto == kHttpClientRuntimeWaitUpgrade && info.connection_upgrade &&
                httpclientUpgradeIsH2C(ts) && info.upgrade_h2c &&
                httpclientValidateRequiredHeaders(header_text, ts->upgrade_response_headers))
            {
                ls->h1_upgrade_accepted = true;
                ls->runtime_proto       = kHttpClientRuntimeAfterUpgrade;
                ls->h1_headers_parsed   = true;

                if (! httpclientTransportHandleUpgradeAccepted(t, l, ls))
                {
                    memoryFree(header_text);
                    return false;
                }

                memoryFree(header_text);

                while (! bufferstreamIsEmpty(&ls->in_stream))
                {
                    sbuf_t *leftover = bufferstreamIdealRead(&ls->in_stream);
                    if (! httpclientTransportFeedHttp2Input(t, l, ls, leftover))
                    {
                        return false;
                    }
                }

                return httpclientTransportFlushPendingUp(t, l, ls);
            }

            memoryFree(header_text);
            LOGE("HttpClient: unexpected HTTP/1.1 101 response");
            return false;
        }

        if (info.status_code >= 100 && info.status_code < 200)
        {
            memoryFree(header_text);
            continue;
        }

        ls->runtime_proto       = kHttpClientRuntimeHttp1;
        ls->h1_headers_parsed   = true;
        ls->h1_response_chunked = info.transfer_chunked;

        if (ts->verbose)
        {
            LOGD("HttpClient: parsed HTTP/1.1 response status=%d chunked=%s content-length=%s body-remaining=%" PRId64,
                 info.status_code, info.transfer_chunked ? "true" : "false",
                 info.has_content_length ? "true" : "false", info.content_length);
        }

        if (info.transfer_chunked && info.has_content_length)
        {
            LOGE("HttpClient: invalid HTTP/1.1 response (both Transfer-Encoding and Content-Length)");
            memoryFree(header_text);
            return false;
        }

        bool response_has_no_body = false;
        if (info.status_code == 204 || info.status_code == 304 || (info.status_code >= 100 && info.status_code < 200))
        {
            response_has_no_body = true;
        }

        if (httpclientEffectiveMethodEnum(ts, ls) == kHttpHead)
        {
            response_has_no_body = true;
        }

        if (response_has_no_body)
        {
            ls->h1_body_mode      = kHttpClientH1BodyNone;
            ls->response_complete = true;
            memoryFree(header_text);
            return true;
        }

        if (info.transfer_chunked)
        {
            ls->h1_body_mode      = kHttpClientH1BodyChunked;
            ls->h1_chunk_expected = -1;
        }
        else if (info.has_content_length)
        {
            ls->h1_body_mode      = kHttpClientH1BodyContentLen;
            ls->h1_body_remaining = info.content_length;
            if (ls->h1_body_remaining == 0)
            {
                ls->response_complete = true;
                memoryFree(header_text);
                return true;
            }
        }
        else
        {
            ls->h1_body_mode = kHttpClientH1BodyUntilClose;
        }

        memoryFree(header_text);
        return httpclientTransportFlushPendingUp(t, l, ls);
    }

    return true;
}

static bool parseChunkSizeLine(sbuf_t *line_buf, uint64_t *chunk_len)
{
    size_t raw_len = sbufGetLength(line_buf);
    if (raw_len < 2)
    {
        return false;
    }

    size_t line_len = raw_len - 2;
    char  *line     = memoryAllocate(line_len + 1);
    memoryCopy(line, sbufGetRawPtr(line_buf), line_len);
    line[line_len] = '\0';

    char *semi = strchr(line, ';');
    if (semi != NULL)
    {
        *semi = '\0';
    }

    char *endp                = NULL;
    unsigned long long parsed = strtoull(line, &endp, 16);
    while (endp != NULL && (*endp == ' ' || *endp == '\t'))
    {
        ++endp;
    }

    bool ok = (endp != NULL && endp != line && *endp == '\0');

    memoryFree(line);

    if (! ok)
    {
        return false;
    }

    *chunk_len = (uint64_t) parsed;
    return true;
}

bool httpclientTransportDrainHttp1ChunkedBody(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    while (true)
    {
        if (ls->h1_chunk_expected < 0)
        {
            size_t line_end = 0;
            if (! bufferstreamFindCRLF(&ls->in_stream, &line_end))
            {
                return true;
            }

            sbuf_t *line_buf = bufferstreamReadExact(&ls->in_stream, line_end + 2);

            uint64_t chunk_len = 0;
            bool     ok        = parseChunkSizeLine(line_buf, &chunk_len);
            lineReuseBuffer(l, line_buf);

            if (! ok || chunk_len > (uint64_t) INT64_MAX)
            {
                LOGE("HttpClient: invalid chunked size line");
                return false;
            }

            ls->h1_chunk_expected = (int64_t) chunk_len;

            if (ls->h1_chunk_expected == 0)
            {
                while (true)
                {
                    size_t trailer_line_end = 0;
                    if (! bufferstreamFindCRLF(&ls->in_stream, &trailer_line_end))
                    {
                        return true;
                    }

                    sbuf_t *trailer_line = bufferstreamReadExact(&ls->in_stream, trailer_line_end + 2);
                    bool    done         = (trailer_line_end == 0);
                    lineReuseBuffer(l, trailer_line);

                    if (done)
                    {
                        if (! ls->prev_finished)
                        {
                            ls->response_complete = true;
                        }
                        return true;
                    }
                }
            }
        }

        if (ls->h1_chunk_expected > 0)
        {
            uint64_t required = (uint64_t) ls->h1_chunk_expected + 2ULL;
            if (bufferstreamGetBufLen(&ls->in_stream) < required)
            {
                return true;
            }

            sbuf_t *chunk_with_tail = bufferstreamReadExact(&ls->in_stream, (size_t) required);

            uint32_t full_len = sbufGetLength(chunk_with_tail);
            if (full_len < 2)
            {
                lineReuseBuffer(l, chunk_with_tail);
                return false;
            }

            uint8_t *ptr = (uint8_t *) sbufGetMutablePtr(chunk_with_tail);
            if (ptr[full_len - 2] != '\r' || ptr[full_len - 1] != '\n')
            {
                lineReuseBuffer(l, chunk_with_tail);
                LOGE("HttpClient: invalid chunked frame tail");
                return false;
            }

            sbufSetLength(chunk_with_tail, (uint32_t) ls->h1_chunk_expected);

            if (! httpclientForwardDownstreamPayload(t, l, ls, chunk_with_tail))
            {
                return false;
            }

            ls->h1_chunk_expected = -1;
            continue;
        }
    }
}

bool httpclientTransportDrainHttp1Body(tunnel_t *t, line_t *l, httpclient_lstate_t *ls)
{
    if (ls->prev_finished || ls->h1_body_mode == kHttpClientH1BodyNone)
    {
        return true;
    }

    if (ls->h1_body_mode == kHttpClientH1BodyChunked)
    {
        return httpclientTransportDrainHttp1ChunkedBody(t, l, ls);
    }

    if (ls->h1_body_mode == kHttpClientH1BodyUntilClose)
    {
        while (! bufferstreamIsEmpty(&ls->in_stream))
        {
            sbuf_t *buf = bufferstreamIdealRead(&ls->in_stream);
            if (! httpclientForwardDownstreamPayload(t, l, ls, buf))
            {
                return false;
            }
        }
        return true;
    }

    while (ls->h1_body_remaining > 0)
    {
        size_t available = bufferstreamGetBufLen(&ls->in_stream);
        if (available == 0)
        {
            return true;
        }

        uint64_t to_read64 = min((uint64_t) available, (uint64_t) ls->h1_body_remaining);
        size_t   to_read   = (size_t) to_read64;
        sbuf_t  *buf       = bufferstreamReadExact(&ls->in_stream, to_read);

        ls->h1_body_remaining -= (int64_t) to_read;

        if (! httpclientForwardDownstreamPayload(t, l, ls, buf))
        {
            return false;
        }
    }

    if (ls->h1_body_remaining == 0 && ! ls->prev_finished)
    {
        ls->response_complete = true;
        return true;
    }

    return true;
}
