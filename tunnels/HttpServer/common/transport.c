#include "structure.h"

#include "loggers/network_logger.h"
#include "utils/sha1.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>

typedef struct httpserver_h1_request_info_s
{
    char method[32];
    char path[2048];
    char host[512];
    char upgrade_value[256];
    char http2_settings[512];
    char sec_websocket_key[128];
    char sec_websocket_protocol[256];
    char origin[512];

    bool    transfer_chunked;
    bool    connection_upgrade;
    bool    connection_http2_settings;
    bool    has_upgrade_header;
    bool    upgrade_h2c;
    bool    upgrade_websocket;
    bool    has_http2_settings;
    bool    has_content_length;
    bool    has_sec_websocket_key;
    bool    has_sec_websocket_protocol;
    bool    has_origin;
    bool    has_sec_websocket_version;
    int64_t content_length;
    int     sec_websocket_version;
} httpserver_h1_request_info_t;

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

static int  httpserverOnHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                       size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                                       void *userdata);
static int  httpserverOnDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                              const uint8_t *data, size_t len, void *userdata);
static int  httpserverOnFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata);
static int  httpserverOnStreamClosedCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                             void *userdata);

static bool httpserverVerboseEnabled(tunnel_t *t)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    return ts->verbose;
}

static const char *httpserverWebSocketOpcodeName(uint8_t opcode)
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

static bool base64UrlDecode(const char *src, uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    if (src == NULL || dst == NULL || out_len == NULL)
    {
        return false;
    }

    size_t src_len = strlen(src);
    char  *cleaned = memoryAllocate(src_len + 1);
    size_t clean_len = 0;

    bool seen_padding = false;
    for (size_t i = 0; i < src_len; ++i)
    {
        char c = src[i];
        if (c == ' ' || c == '\t')
        {
            continue;
        }

        if (c == '=')
        {
            seen_padding = true;
            continue;
        }

        if (seen_padding)
        {
            memoryFree(cleaned);
            return false;
        }

        cleaned[clean_len++] = c;
    }
    cleaned[clean_len] = '\0';

    size_t i = 0;
    size_t o = 0;

    while (i < clean_len)
    {
        uint8_t in[4] = {0};
        size_t  in_len = 0;

        while (i < clean_len && in_len < 4)
        {
            char c = cleaned[i++];

            if (c >= 'A' && c <= 'Z')
            {
                in[in_len++] = (uint8_t) (c - 'A');
            }
            else if (c >= 'a' && c <= 'z')
            {
                in[in_len++] = (uint8_t) (26 + (c - 'a'));
            }
            else if (c >= '0' && c <= '9')
            {
                in[in_len++] = (uint8_t) (52 + (c - '0'));
            }
            else if (c == '-')
            {
                in[in_len++] = 62;
            }
            else if (c == '_')
            {
                in[in_len++] = 63;
            }
            else
            {
                memoryFree(cleaned);
                return false;
            }
        }

        if (in_len == 0)
        {
            break;
        }

        if (in_len == 1)
        {
            memoryFree(cleaned);
            return false;
        }

        if (o + (in_len - 1) > dst_cap)
        {
            memoryFree(cleaned);
            return false;
        }

        uint32_t v = ((uint32_t) in[0] << 18) | ((uint32_t) in[1] << 12) | ((uint32_t) in[2] << 6) | (uint32_t) in[3];
        dst[o++]   = (uint8_t) ((v >> 16) & 0xFF);
        if (in_len >= 3)
        {
            dst[o++] = (uint8_t) ((v >> 8) & 0xFF);
        }
        if (in_len == 4)
        {
            dst[o++] = (uint8_t) (v & 0xFF);
        }
    }

    memoryFree(cleaned);
    *out_len = o;
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

static bool httpserverHeaderNameEquals(const char *value, const char *name)
{
    return httpserverStringCaseEquals(value, name);
}

static const char *httpserverUpgradeProtocol(const httpserver_tstate_t *ts)
{
    if (ts == NULL || ts->upgrade_protocol == NULL || ts->upgrade_protocol[0] == '\0')
    {
        return "h2c";
    }

    return ts->upgrade_protocol;
}

static bool httpserverUpgradeIsH2C(const httpserver_tstate_t *ts)
{
    return ts != NULL && httpserverStringCaseEquals(httpserverUpgradeProtocol(ts), "h2c");
}

static bool httpserverUpgradeIsCustom(const httpserver_tstate_t *ts)
{
    return ts != NULL && ! httpserverUpgradeIsH2C(ts);
}

static bool httpserverShouldSkipExtraHeader(const char *name, bool websocket_mode)
{
    if (name == NULL)
    {
        return true;
    }

    if (httpserverHeaderNameEquals(name, "content-length"))
    {
        return true;
    }

    if (websocket_mode)
    {
        return httpserverHeaderNameEquals(name, "connection") || httpserverHeaderNameEquals(name, "upgrade") ||
               httpserverHeaderNameEquals(name, "transfer-encoding") ||
               httpserverHeaderNameEquals(name, "sec-websocket-accept") ||
               httpserverHeaderNameEquals(name, "sec-websocket-protocol") ||
               httpserverHeaderNameEquals(name, "sec-websocket-extensions") ||
               httpserverHeaderNameEquals(name, "content-type");
    }

    return httpserverHeaderNameEquals(name, "connection") || httpserverHeaderNameEquals(name, "transfer-encoding");
}

static bool httpserverShouldSkipUpgradeExtraHeader(const char *name)
{
    if (name == NULL)
    {
        return true;
    }

    return httpserverHeaderNameEquals(name, "connection") || httpserverHeaderNameEquals(name, "upgrade") ||
           httpserverHeaderNameEquals(name, "http2-settings");
}

static bool httpserverFindHeaderValue(const char *headers, const char *name, char *out, size_t out_cap)
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

static bool httpserverValidateRequiredHeaders(const char *headers, const cJSON *required)
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

        if (httpserverShouldSkipUpgradeExtraHeader(header->string))
        {
            continue;
        }

        if (! httpserverFindHeaderValue(headers, header->string, found_value, sizeof(found_value)))
        {
            return false;
        }

        if (! httpserverStringCaseEquals(found_value, header->valuestring))
        {
            return false;
        }
    }

    return true;
}

static void httpserverBuildWebSocketAccept(const char *key, char *out, size_t out_cap)
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

static size_t minSize(size_t a, size_t b)
{
    return a < b ? a : b;
}

static bool sendBytesDown(tunnel_t *t, line_t *l, const void *data, uint32_t len)
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
        sbuf_t  *buf   = httpserverAllocBufferForLength(l, chunk);

        sbufSetLength(buf, chunk);
        sbufWriteLarge(buf, ptr, chunk);

        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
        {
            return false;
        }

        ptr += chunk;
        rem -= chunk;
    }

    return true;
}

static bool sendTextDown(tunnel_t *t, line_t *l, const char *text)
{
    return sendBytesDown(t, l, text, (uint32_t) strlen(text));
}

static bool httpserverSendRawDown(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *buf)
{
    if (buf == NULL)
    {
        return true;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        return httpserverTransportSendHttp2DataFrame(t, l, ls, buf, false);
    }

    return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf);
}

static bool httpserverSendRawBytesDown(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, const void *data, uint32_t len)
{
    if (len == 0)
    {
        return true;
    }

    if (ls->runtime_proto == kHttpServerRuntimeHttp2)
    {
        sbuf_t *buf = httpserverAllocBufferForLength(l, len);
        sbufSetLength(buf, len);
        sbufWriteLarge(buf, data, len);
        return httpserverTransportSendHttp2DataFrame(t, l, ls, buf, false);
    }

    return sendBytesDown(t, l, data, len);
}

static size_t httpserverBuildWebSocketHeader(uint8_t *header, size_t cap, uint8_t opcode, uint64_t payload_len)
{
    if (cap < 2)
    {
        return 0;
    }

    size_t off   = 0;
    header[off++] = (uint8_t) (0x80U | (opcode & 0x0FU));

    if (payload_len <= 125U)
    {
        header[off++] = (uint8_t) payload_len;
    }
    else if (payload_len <= 0xFFFFU)
    {
        if (cap < off + 3)
        {
            return 0;
        }
        header[off++] = 126U;
        header[off++] = (uint8_t) ((payload_len >> 8) & 0xFFU);
        header[off++] = (uint8_t) (payload_len & 0xFFU);
    }
    else
    {
        if (cap < off + 9)
        {
            return 0;
        }
        header[off++] = 127U;
        for (int shift = 56; shift >= 0; shift -= 8)
        {
            header[off++] = (uint8_t) ((payload_len >> shift) & 0xFFU);
        }
    }

    return off;
}

static bool httpserverSendWebSocketControlFrame(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, uint8_t opcode,
                                                const void *payload, uint32_t payload_len)
{
    uint8_t header[16];
    size_t  header_len = httpserverBuildWebSocketHeader(header, sizeof(header), opcode, payload_len);
    if (header_len == 0)
    {
        return false;
    }

    if (! httpserverSendRawBytesDown(t, l, ls, header, (uint32_t) header_len))
    {
        return false;
    }

    if (payload_len == 0)
    {
        return true;
    }

    sbuf_t *buf = httpserverAllocBufferForLength(l, payload_len);
    sbufSetLength(buf, payload_len);
    sbufWriteLarge(buf, payload, payload_len);
    return httpserverSendRawDown(t, l, ls, buf);
}

static line_t *httpserverUpstreamTargetLine(httpserver_lstate_t *ls, line_t *fallback)
{
    if (ls->split_role == kHttpServerSplitRoleUpload && ls->split_main_line != NULL)
    {
        return ls->split_main_line;
    }
    return fallback;
}

static bool httpserverForwardUpstreamPayload(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *buf)
{
    line_t *target = httpserverUpstreamTargetLine(ls, l);
    if (target == NULL || ! lineIsAlive(target))
    {
        lineReuseBuffer(l, buf);
        return false;
    }
    return withLineLockedWithBuf(target, tunnelNextUpStreamPayload, t, buf);
}

static void httpserverForwardUpstreamFinish(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    line_t *target = httpserverUpstreamTargetLine(ls, l);
    if (target != NULL && lineIsAlive(target))
    {
        tunnelNextUpStreamFinish(t, target);
    }
}

static const char *statusReasonPhrase(int status_code)
{
    const char *reason = httpStatusStr((enum http_status) status_code);

    if (reason == NULL || stringCompare(reason, "<unknown>") == 0)
    {
        return "OK";
    }

    return reason;
}

bool httpserverTransportSendHttp1ResponseHeaders(tunnel_t *t, line_t *l)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ts->verbose)
    {
        LOGD("HttpServer: sending HTTP/1.1 response status=%d websocket=false", ts->status_code);
    }

    char *header_buf = memoryAllocate(kHttpServerMaxHeaderBytes);
    int  offset = 0;

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "HTTP/1.1 %d %s\r\n", ts->status_code,
                          statusReasonPhrase(ts->status_code)) ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset,
                          "Connection: close\r\nTransfer-Encoding: chunked\r\n"))
    {
        LOGE("HttpServer: response headers are too large");
        memoryFree(header_buf);
        return false;
    }

    if (ts->content_type != kContentTypeNone && ts->content_type != kContentTypeUndefined)
    {
        if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Content-Type: %s\r\n",
                              httpContentTypeStr(ts->content_type)))
        {
            LOGE("HttpServer: response headers are too large");
            memoryFree(header_buf);
            return false;
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

            if (httpserverShouldSkipExtraHeader(header->string, false))
            {
                continue;
            }

            if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                  header->valuestring))
            {
                LOGE("HttpServer: response headers are too large");
                memoryFree(header_buf);
                return false;
            }
        }
    }

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "\r\n"))
    {
        LOGE("HttpServer: response headers are too large");
        memoryFree(header_buf);
        return false;
    }

    bool ok = sendBytesDown(t, l, header_buf, (uint32_t) offset);
    memoryFree(header_buf);
    return ok;
}

static bool httpserverTransportSendHttp1WebSocketResponseHeaders(tunnel_t *t, line_t *l,
                                                                 const httpserver_h1_request_info_t *info)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    char                *header_buf = memoryAllocate(kHttpServerMaxHeaderBytes);
    int                  offset     = 0;
    char                 accept[128];

    httpserverBuildWebSocketAccept(info->sec_websocket_key, accept, sizeof(accept));
    if (accept[0] == '\0')
    {
        memoryFree(header_buf);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("HttpServer: accepting websocket HTTP/1.1 upgrade path=%s host=%s protocol=%s", info->path, info->host,
             ts->websocket_subprotocol != NULL ? ts->websocket_subprotocol : "<none>");
    }

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "HTTP/1.1 101 Switching Protocols\r\n") ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Connection: Upgrade\r\n") ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Upgrade: websocket\r\n") ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Sec-WebSocket-Accept: %s\r\n", accept))
    {
        memoryFree(header_buf);
        return false;
    }

    if (ts->websocket_subprotocol != NULL &&
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Sec-WebSocket-Protocol: %s\r\n",
                          ts->websocket_subprotocol))
    {
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

            if (httpserverShouldSkipExtraHeader(header->string, true))
            {
                continue;
            }

            if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                  header->valuestring))
            {
                memoryFree(header_buf);
                return false;
            }
        }
    }

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "\r\n"))
    {
        memoryFree(header_buf);
        return false;
    }

    bool ok = sendBytesDown(t, l, header_buf, (uint32_t) offset);
    memoryFree(header_buf);
    return ok;
}

static bool httpserverTransportSendHttp1UpgradeResponseHeaders(tunnel_t *t, line_t *l, const char *protocol)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (protocol == NULL || protocol[0] == '\0')
    {
        return false;
    }

    if (ts->verbose)
    {
        LOGD("HttpServer: accepting HTTP/1.1 upgrade protocol=%s", protocol);
    }

    char *header_buf = memoryAllocate(kHttpServerMaxHeaderBytes);
    int   offset     = 0;

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "HTTP/1.1 101 Switching Protocols\r\n") ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Connection: Upgrade\r\n") ||
        ! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "Upgrade: %s\r\n", protocol))
    {
        memoryFree(header_buf);
        return false;
    }

    if (cJSON_IsObject(ts->upgrade_response_headers))
    {
        cJSON *header = NULL;
        cJSON_ArrayForEach(header, ts->upgrade_response_headers)
        {
            if (! cJSON_IsString(header) || header->valuestring == NULL || header->string == NULL)
            {
                continue;
            }

            if (httpserverShouldSkipUpgradeExtraHeader(header->string))
            {
                continue;
            }

            if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "%s: %s\r\n", header->string,
                                  header->valuestring))
            {
                memoryFree(header_buf);
                return false;
            }
        }
    }

    if (! appendHeaderFmt(header_buf, kHttpServerMaxHeaderBytes, &offset, "\r\n"))
    {
        memoryFree(header_buf);
        return false;
    }

    bool ok = sendBytesDown(t, l, header_buf, (uint32_t) offset);
    memoryFree(header_buf);
    return ok;
}

bool httpserverTransportSendHttp1FinalChunk(tunnel_t *t, line_t *l)
{
    return sendTextDown(t, l, "0\r\n\r\n");
}

bool httpserverTransportSendHttp1ChunkedPayload(tunnel_t *t, line_t *l, sbuf_t *payload)
{
    uint32_t payload_len = sbufGetLength(payload);

    char chunk_prefix[32];
    int  prefix_len = snprintf(chunk_prefix, sizeof(chunk_prefix), "%x\r\n", payload_len);

    if (prefix_len <= 0)
    {
        return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, payload);
    }

    if (sbufGetLeftCapacity(payload) >= (uint32_t) prefix_len)
    {
        sbufShiftLeft(payload, (uint32_t) prefix_len);
        sbufWrite(payload, chunk_prefix, (uint32_t) prefix_len);
    }
    else
    {
        if (! sendBytesDown(t, l, chunk_prefix, (uint32_t) prefix_len))
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

    if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, payload))
    {
        return false;
    }

    if (! appended_tail)
    {
        if (! sendTextDown(t, l, "\r\n"))
        {
            return false;
        }
    }

    return true;
}

static bool hostMatchesExpected(const char *expected, const char *actual)
{
    if (expected == NULL || expected[0] == '\0')
    {
        return true;
    }

    if (actual == NULL || actual[0] == '\0')
    {
        return false;
    }

    if (httpserverStringCaseEquals(expected, actual))
    {
        return true;
    }

    const char *colon = strchr(actual, ':');
    if (colon == NULL)
    {
        return false;
    }

    size_t host_len = (size_t) (colon - actual);
    size_t exp_len  = strlen(expected);

    if (host_len != exp_len)
    {
        return false;
    }

    for (size_t i = 0; i < host_len; i++)
    {
        if ((char) tolower((unsigned char) actual[i]) != (char) tolower((unsigned char) expected[i]))
        {
            return false;
        }
    }

    return true;
}

static bool parseHttp1RequestHeaders(const char *headers, httpserver_h1_request_info_t *info)
{
    if (headers == NULL || info == NULL)
    {
        return false;
    }

    *info = (httpserver_h1_request_info_t){0};

    char *tmp = stringDuplicate(headers);

    char *line_end = strstr(tmp, "\r\n");
    if (line_end == NULL)
    {
        memoryFree(tmp);
        return false;
    }

    *line_end = '\0';

    char method[sizeof(info->method)] = {0};
    char path[sizeof(info->path)]     = {0};

    if (sscanf(tmp, "%31s %2047s HTTP/%*d.%*d", method, path) != 2)
    {
        memoryFree(tmp);
        return false;
    }

    snprintf(info->method, sizeof(info->method), "%s", method);
    snprintf(info->path, sizeof(info->path), "%s", path);

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

            if (httpserverStringCaseEquals(key, "Transfer-Encoding") && httpserverStringCaseContainsToken(value, "chunked"))
            {
                info->transfer_chunked = true;
            }
            else if (httpserverStringCaseEquals(key, "Connection"))
            {
                if (httpserverStringCaseContainsToken(value, "upgrade"))
                {
                    info->connection_upgrade = true;
                }
                if (httpserverStringCaseContainsToken(value, "http2-settings"))
                {
                    info->connection_http2_settings = true;
                }
            }
            else if (httpserverStringCaseEquals(key, "Upgrade") && httpserverStringCaseContains(value, "h2c"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
                info->upgrade_h2c = true;
            }
            else if (httpserverStringCaseEquals(key, "Upgrade") && httpserverStringCaseContains(value, "websocket"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
                info->upgrade_websocket = true;
            }
            else if (httpserverStringCaseEquals(key, "Upgrade"))
            {
                info->has_upgrade_header = true;
                snprintf(info->upgrade_value, sizeof(info->upgrade_value), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "HTTP2-Settings"))
            {
                if (info->has_http2_settings)
                {
                    memoryFree(tmp);
                    return false;
                }

                info->has_http2_settings = true;
                snprintf(info->http2_settings, sizeof(info->http2_settings), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "Host"))
            {
                snprintf(info->host, sizeof(info->host), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "Content-Length"))
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
            else if (httpserverStringCaseEquals(key, "Sec-WebSocket-Key"))
            {
                info->has_sec_websocket_key = true;
                snprintf(info->sec_websocket_key, sizeof(info->sec_websocket_key), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "Sec-WebSocket-Protocol"))
            {
                info->has_sec_websocket_protocol = true;
                snprintf(info->sec_websocket_protocol, sizeof(info->sec_websocket_protocol), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "Origin"))
            {
                info->has_origin = true;
                snprintf(info->origin, sizeof(info->origin), "%s", value);
            }
            else if (httpserverStringCaseEquals(key, "Sec-WebSocket-Version"))
            {
                info->has_sec_websocket_version = true;
                info->sec_websocket_version     = atoi(value);
            }
        }

        line = next + 2;
    }

    memoryFree(tmp);
    return true;
}

static bool validateHttp1Request(const httpserver_tstate_t *ts, const httpserver_h1_request_info_t *info)
{
    if (ts->expected_method != NULL && ts->expected_method[0] != '\0' && ! httpserverStringCaseEquals(ts->expected_method, info->method))
    {
        LOGW("HttpServer: method mismatch, expected=%s got=%s", ts->expected_method, info->method);
        return false;
    }

    if (ts->expected_path != NULL && ts->expected_path[0] != '\0' && stringCompare(ts->expected_path, info->path) != 0)
    {
        LOGW("HttpServer: path mismatch, expected=%s got=%s", ts->expected_path, info->path);
        return false;
    }

    if (! hostMatchesExpected(ts->expected_host, info->host))
    {
        LOGW("HttpServer: host mismatch, expected=%s got=%s", ts->expected_host, info->host);
        return false;
    }

    return true;
}

static bool validateWebSocketHttp1Request(const httpserver_tstate_t *ts, const httpserver_h1_request_info_t *info)
{
    if (! httpserverStringCaseEquals(info->method, "GET"))
    {
        LOGW("HttpServer: websocket HTTP/1.1 request must use GET");
        return false;
    }

    if (ts->expected_path != NULL && ts->expected_path[0] != '\0' && stringCompare(ts->expected_path, info->path) != 0)
    {
        LOGW("HttpServer: websocket path mismatch, expected=%s got=%s", ts->expected_path, info->path);
        return false;
    }

    if (! hostMatchesExpected(ts->expected_host, info->host))
    {
        LOGW("HttpServer: websocket host mismatch expected=%s got=%s", ts->expected_host, info->host);
        return false;
    }

    if (! info->connection_upgrade || ! info->upgrade_websocket || ! info->has_sec_websocket_key ||
        ! info->has_sec_websocket_version || info->sec_websocket_version != 13)
    {
        LOGW("HttpServer: websocket HTTP/1.1 handshake headers are invalid");
        return false;
    }

    if (info->transfer_chunked || (info->has_content_length && info->content_length > 0))
    {
        LOGW("HttpServer: websocket HTTP/1.1 upgrade request must not carry a body transfer-chunked=%s content-length=%" PRId64,
             info->transfer_chunked ? "true" : "false", info->content_length);
        return false;
    }

    if (ts->websocket_origin != NULL &&
        (! info->has_origin || ! httpserverStringCaseEquals(ts->websocket_origin, info->origin)))
    {
        LOGW("HttpServer: websocket origin mismatch");
        return false;
    }

    if (ts->websocket_subprotocol != NULL &&
        (! info->has_sec_websocket_protocol ||
         ! httpserverStringCaseContainsToken(info->sec_websocket_protocol, ts->websocket_subprotocol)))
    {
        LOGW("HttpServer: websocket subprotocol mismatch");
        return false;
    }

    return true;
}

static bool sendNghttp2Outbound(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
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
            LOGE("HttpServer: nghttp2_session_mem_send2 failed");
            return false;
        }

        if (len == 0)
        {
            break;
        }

        if ((uint64_t) len > UINT32_MAX)
        {
            LOGE("HttpServer: outgoing HTTP/2 frame exceeds buffer limits");
            return false;
        }

        uint32_t        rem = (uint32_t) len;
        const uint8_t  *ptr = data;
        while (rem > 0)
        {
            uint32_t chunk = min(rem, max_chunk);
            sbuf_t  *buf   = httpserverAllocBufferForLength(l, chunk);
            sbufSetLength(buf, chunk);
            sbufWriteLarge(buf, ptr, chunk);

            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, buf))
            {
                return false;
            }

            ptr += chunk;
            rem -= chunk;
        }
    }

    return true;
}

static bool httpserverTransportEnsureHttp2SessionInternal(tunnel_t *t, line_t *l, httpserver_lstate_t *ls,
                                                          bool flush_outbound)
{
    if (ls->session != NULL)
    {
        ls->runtime_proto = kHttpServerRuntimeHttp2;
        return flush_outbound ? sendNghttp2Outbound(t, l, ls) : true;
    }

    httpserver_tstate_t *ts = tunnelGetState(t);

    nghttp2_session_callbacks_set_on_header_callback(ts->cbs, httpserverOnHeaderCallback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ts->cbs, httpserverOnDataChunkRecvCallback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(ts->cbs, httpserverOnFrameRecvCallback);
    nghttp2_session_callbacks_set_on_stream_close_callback(ts->cbs, httpserverOnStreamClosedCallback);

    if (nghttp2_session_server_new3(&ls->session, ts->cbs, ls, ts->ngoptions, NULL) != 0)
    {
        LOGE("HttpServer: nghttp2_session_server_new3 failed");
        return false;
    }

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 20)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (uint32_t) kHttpServerHttp2FrameBytes},
        {NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, ts->websocket_enabled ? 1U : 0U}
    };

    if (nghttp2_submit_settings(ls->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings)) != 0)
    {
        LOGE("HttpServer: nghttp2_submit_settings failed");
        return false;
    }

    ls->runtime_proto = kHttpServerRuntimeHttp2;

    if (ts->verbose)
    {
        LOGD("HttpServer: initialized HTTP/2 server session websocket=%s flush-outbound=%s",
             ts->websocket_enabled ? "true" : "false", flush_outbound ? "true" : "false");
    }

    return flush_outbound ? sendNghttp2Outbound(t, l, ls) : true;
}

static bool validateWebSocketHttp2Request(const httpserver_tstate_t *ts, const httpserver_lstate_t *ls)
{
    if (! ls->websocket_h2_method_seen || ! ls->websocket_h2_protocol_seen || ! ls->websocket_h2_path_seen ||
        ! ls->websocket_h2_authority_seen || ! ls->websocket_h2_version_seen)
    {
        return false;
    }

    if (! httpserverStringCaseEquals(ls->websocket_h2_method, "CONNECT") ||
        ! httpserverStringCaseEquals(ls->websocket_h2_protocol, "websocket") ||
        stringCompare(ls->websocket_h2_path, ts->expected_path) != 0 ||
        ! hostMatchesExpected(ts->expected_host, ls->websocket_h2_authority) ||
        stringCompare(ls->websocket_h2_version, "13") != 0)
    {
        return false;
    }

    if (ts->websocket_origin != NULL &&
        (! ls->websocket_h2_origin_seen || ! httpserverStringCaseEquals(ts->websocket_origin, ls->websocket_h2_origin)))
    {
        return false;
    }

    if (ts->websocket_subprotocol != NULL &&
        (! ls->websocket_h2_subprotocol_seen ||
         ! httpserverStringCaseContainsToken(ls->websocket_h2_subprotocol, ts->websocket_subprotocol)))
    {
        return false;
    }

    return true;
}

static int httpserverOnHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                                      size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                                      void *userdata)
{
    discard session;
    discard flags;

    if (userdata == NULL)
    {
        return 0;
    }

    httpserver_lstate_t *ls = (httpserver_lstate_t *) userdata;

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
    {
        return 0;
    }

    if (ls->h2_stream_id != 0 && frame->hd.stream_id != ls->h2_stream_id)
    {
        if (ls->h2_reject_extra_streams)
        {
            nghttp2_submit_rst_stream(ls->session, NGHTTP2_FLAG_NONE, frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
        }
        return 0;
    }

    httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (! ts->websocket_enabled || name == NULL || value == NULL)
    {
        return 0;
    }

    if (namelen == 7 && memoryCompare(name, ":method", 7) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_method) - 1U);
        memoryCopy(ls->websocket_h2_method, value, copy_len);
        ls->websocket_h2_method[copy_len] = '\0';
        ls->websocket_h2_method_seen      = true;
    }
    else if (namelen == 9 && memoryCompare(name, ":protocol", 9) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_protocol) - 1U);
        memoryCopy(ls->websocket_h2_protocol, value, copy_len);
        ls->websocket_h2_protocol[copy_len] = '\0';
        ls->websocket_h2_protocol_seen      = true;
    }
    else if (namelen == 5 && memoryCompare(name, ":path", 5) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_path) - 1U);
        memoryCopy(ls->websocket_h2_path, value, copy_len);
        ls->websocket_h2_path[copy_len] = '\0';
        ls->websocket_h2_path_seen      = true;
    }
    else if (namelen == 10 && memoryCompare(name, ":authority", 10) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_authority) - 1U);
        memoryCopy(ls->websocket_h2_authority, value, copy_len);
        ls->websocket_h2_authority[copy_len] = '\0';
        ls->websocket_h2_authority_seen      = true;
    }
    else if (namelen == 21 && memoryCompare(name, "sec-websocket-version", 21) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_version) - 1U);
        memoryCopy(ls->websocket_h2_version, value, copy_len);
        ls->websocket_h2_version[copy_len] = '\0';
        ls->websocket_h2_version_seen      = true;
    }
    else if (namelen == 22 && memoryCompare(name, "sec-websocket-protocol", 22) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_subprotocol) - 1U);
        memoryCopy(ls->websocket_h2_subprotocol, value, copy_len);
        ls->websocket_h2_subprotocol[copy_len] = '\0';
        ls->websocket_h2_subprotocol_seen      = true;
    }
    else if (namelen == 6 && memoryCompare(name, "origin", 6) == 0)
    {
        size_t copy_len = min(valuelen, sizeof(ls->websocket_h2_origin) - 1U);
        memoryCopy(ls->websocket_h2_origin, value, copy_len);
        ls->websocket_h2_origin[copy_len] = '\0';
        ls->websocket_h2_origin_seen      = true;
    }

    return 0;
}

static int httpserverOnDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                             const uint8_t *data, size_t len, void *userdata)
{
    discard session;
    discard flags;

    if (userdata == NULL || len == 0)
    {
        return 0;
    }

    httpserver_lstate_t *ls = (httpserver_lstate_t *) userdata;

    if (ls->h2_stream_id != 0 && stream_id != ls->h2_stream_id)
    {
        return 0;
    }

    httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ts->verbose)
    {
        LOGD("HttpServer: received HTTP/2 DATA stream_id=%d payload_len=%zu flags=0x%02x", stream_id, len, flags);
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
        sbuf_t  *buf   = httpserverAllocBufferForLength(ls->line, chunk);
        sbufSetLength(buf, chunk);
        sbufWriteLarge(buf, ptr, chunk);
        if (ts->websocket_enabled)
        {
            bufferstreamPush(&ls->in_stream, buf);
        }
        else
        {
            contextqueuePush(&ls->events_up, contextCreatePayload(ls->line, buf));
        }
        ptr += chunk;
        rem -= chunk;
    }

    return 0;
}

static int httpserverOnFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *userdata)
{
    discard session;

    if (userdata == NULL)
    {
        return 0;
    }

    httpserver_lstate_t *ls = (httpserver_lstate_t *) userdata;

    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST)
    {
        if (ls->h2_stream_id == 0)
        {
            ls->h2_stream_id = frame->hd.stream_id;
        }
        else if (frame->hd.stream_id != ls->h2_stream_id)
        {
            if (ls->h2_reject_extra_streams)
            {
                nghttp2_submit_rst_stream(ls->session, NGHTTP2_FLAG_NONE, frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
            }
            return 0;
        }

        httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
        if (ts->verbose)
        {
            LOGD("HttpServer: received HTTP/2 request headers stream_id=%d flags=0x%02x", frame->hd.stream_id,
                 frame->hd.flags);
        }
        if (ts->websocket_enabled)
        {
            ls->websocket_active = validateWebSocketHttp2Request(ts, ls);
            if (ls->websocket_active && ts->verbose)
            {
                LOGD("HttpServer: websocket HTTP/2 handshake accepted stream_id=%d authority=%s path=%s protocol=%s",
                     ls->h2_stream_id, ls->websocket_h2_authority, ls->websocket_h2_path,
                     ls->websocket_h2_subprotocol_seen ? ls->websocket_h2_subprotocol : "<none>");
            }
        }
    }

    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == NGHTTP2_FLAG_END_STREAM && frame->hd.stream_id == ls->h2_stream_id)
    {
        httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
        if (ts->verbose)
        {
            LOGD("HttpServer: received HTTP/2 END_STREAM stream_id=%d websocket=%s full-duplex=%s",
                 frame->hd.stream_id, ts->websocket_enabled ? "true" : "false", ts->full_duplex ? "true" : "false");
        }
        if (! ls->h2_request_finished)
        {
            ls->h2_request_finished = true;
            if (! ts->websocket_enabled && ! ts->full_duplex)
            {
                contextqueuePush(&ls->events_up, contextCreateFin(ls->line));
            }
        }
    }

    return 0;
}

static int httpserverOnStreamClosedCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                                            void *userdata)
{
    discard session;
    discard error_code;

    if (userdata == NULL)
    {
        return 0;
    }

    httpserver_lstate_t *ls = (httpserver_lstate_t *) userdata;

    if (stream_id == ls->h2_stream_id && ! ls->h2_request_finished)
    {
        ls->h2_request_finished = true;
        httpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
        if (! ts->websocket_enabled && ! ts->full_duplex)
        {
            contextqueuePush(&ls->events_up, contextCreateFin(ls->line));
        }
    }

    return 0;
}

bool httpserverTransportEnsureHttp2Session(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    return httpserverTransportEnsureHttp2SessionInternal(t, l, ls, true);
}

bool httpserverTransportPrepareHttp2Session(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    return httpserverTransportEnsureHttp2SessionInternal(t, l, ls, false);
}

static bool httpserverTransportApplyUpgradeSettingsAndOpenStream(tunnel_t *t, line_t *l, httpserver_lstate_t *ls,
                                                                 const char *h2_settings_value, bool flush_outbound)
{
    uint8_t settings_payload[256];
    size_t  settings_len = 0;

    if (! base64UrlDecode(h2_settings_value, settings_payload, sizeof(settings_payload), &settings_len))
    {
        LOGE("HttpServer: invalid HTTP2-Settings header");
        return false;
    }

    if (settings_len == 0)
    {
        LOGE("HttpServer: empty HTTP2-Settings header");
        return false;
    }

    if (! httpserverTransportPrepareHttp2Session(t, l, ls))
    {
        return false;
    }

    if (nghttp2_session_upgrade2(ls->session, settings_payload, settings_len, 0, NULL) != 0)
    {
        LOGE("HttpServer: nghttp2_session_upgrade2 failed");
        return false;
    }

    ls->h2_stream_id  = 1;
    ls->runtime_proto = kHttpServerRuntimeHttp2;

    return flush_outbound ? sendNghttp2Outbound(t, l, ls) : true;
}

bool httpserverTransportSubmitHttp2ResponseHeaders(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, bool end_stream)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->h2_stream_id <= 0)
    {
        return false;
    }

    char status_buf[8];
    snprintf(status_buf, sizeof(status_buf), "%d", ts->websocket_enabled ? 200 : ts->status_code);

    if (ts->verbose)
    {
        LOGD("HttpServer: sending HTTP/2 response headers stream_id=%d status=%s websocket=%s end_stream=%s",
             ls->h2_stream_id, status_buf, ts->websocket_enabled ? "true" : "false", end_stream ? "true" : "false");
    }

    nghttp2_nv nvs[24];
    int        nvlen = 0;

    nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) ":status",
                                 .value = (uint8_t *) status_buf,
                                 .namelen = 7,
                                 .valuelen = stringLength(status_buf),
                                 .flags = NGHTTP2_NV_FLAG_NONE};

    if (! ts->websocket_enabled && ts->content_type != kContentTypeNone && ts->content_type != kContentTypeUndefined)
    {
        const char *ctype = httpContentTypeStr(ts->content_type);
        nvs[nvlen++]      = (nghttp2_nv) {.name = (uint8_t *) "content-type",
                                          .value = (uint8_t *) ctype,
                                          .namelen = 12,
                                          .valuelen = stringLength(ctype),
                                          .flags = NGHTTP2_NV_FLAG_NONE};
    }

    if (ts->websocket_enabled && ts->websocket_subprotocol != NULL)
    {
        nvs[nvlen++] = (nghttp2_nv) {.name = (uint8_t *) "sec-websocket-protocol",
                                     .value = (uint8_t *) ts->websocket_subprotocol,
                                     .namelen = 22,
                                     .valuelen = stringLength(ts->websocket_subprotocol),
                                     .flags = NGHTTP2_NV_FLAG_NONE};
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

            if (header->string[0] == ':' || httpserverShouldSkipExtraHeader(header->string, ts->websocket_enabled))
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

    uint8_t flags = NGHTTP2_FLAG_END_HEADERS;
    if (end_stream)
    {
        flags |= NGHTTP2_FLAG_END_STREAM;
    }

    if (nghttp2_submit_headers(ls->session, flags, ls->h2_stream_id, NULL, nvs, (size_t) nvlen, NULL) != 0)
    {
        LOGE("HttpServer: nghttp2_submit_headers failed");
        return false;
    }

    ls->h2_response_headers_sent = true;

    return sendNghttp2Outbound(t, l, ls);
}

bool httpserverTransportSendHttp2DataFrame(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *payload,
                                           bool end_stream)
{
    if (ls->h2_stream_id <= 0)
    {
        if (payload != NULL)
        {
            bufferqueuePushBack(&ls->pending_down, payload);
        }
        return true;
    }

    uint32_t payload_len = (payload == NULL) ? 0 : sbufGetLength(payload);

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

    uint32_t frame_limit = min((uint32_t) kHttpServerHttp2FrameBytes, remote_max);
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
            return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, payload);
        }

        sbuf_t *header_buf = httpserverAllocBufferForLength(l, HTTP2_FRAME_HDLEN);
        sbufSetLength(header_buf, HTTP2_FRAME_HDLEN);
        http2FrameHdPack(&frame, sbufGetMutablePtr(header_buf));
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, header_buf))
        {
            lineReuseBuffer(l, payload);
            return false;
        }

        return withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, payload);
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

        sbuf_t *header_buf = httpserverAllocBufferForLength(l, HTTP2_FRAME_HDLEN);
        sbufSetLength(header_buf, HTTP2_FRAME_HDLEN);
        http2FrameHdPack(&frame, sbufGetMutablePtr(header_buf));
        if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, header_buf))
        {
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            return false;
        }

        if (frame_payload > 0)
        {
            sbuf_t *data_buf = httpserverAllocBufferForLength(l, frame_payload);
            sbufSetLength(data_buf, frame_payload);
            sbufWriteLarge(data_buf, payload_ptr, frame_payload);
            payload_ptr += frame_payload;
            remaining -= frame_payload;

            if (! withLineLockedWithBuf(l, tunnelPrevDownStreamPayload, t, data_buf))
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

bool httpserverTransportSendWebSocketData(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *payload,
                                          uint8_t opcode)
{
    if (payload == NULL)
    {
        return true;
    }

    uint32_t payload_len = sbufGetLength(payload);
    uint8_t  header[16];
    size_t   header_len = httpserverBuildWebSocketHeader(header, sizeof(header), opcode, payload_len);
    if (header_len == 0)
    {
        lineReuseBuffer(l, payload);
        return false;
    }

    if (sbufGetLeftCapacity(payload) >= header_len)
    {
        sbufShiftLeft(payload, (uint32_t) header_len);
        sbufWrite(payload, header, (uint32_t) header_len);
        return httpserverSendRawDown(t, l, ls, payload);
    }

    if (! httpserverSendRawBytesDown(t, l, ls, header, (uint32_t) header_len))
    {
        lineReuseBuffer(l, payload);
        return false;
    }

    return httpserverSendRawDown(t, l, ls, payload);
}

bool httpserverTransportSendWebSocketClose(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (ls->websocket_close_sent)
    {
        return true;
    }

    ls->websocket_close_sent = true;
    if (httpserverVerboseEnabled(t))
    {
        LOGD("HttpServer: sending websocket close frame");
    }
    return httpserverSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodeClose, NULL, 0);
}

bool httpserverTransportDrainWebSocketUp(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
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

        bool     fin         = (head[0] & 0x80U) != 0;
        uint8_t  opcode      = (uint8_t) (head[0] & 0x0FU);
        bool     masked      = (head[1] & 0x80U) != 0;
        uint64_t payload_len = (uint64_t) (head[1] & 0x7FU);
        size_t   header_len  = 2;
        uint8_t  mask_key[4] = {0};

        if (! masked)
        {
            LOGE("HttpServer: client websocket frames must be masked opcode=%s payload_len=%" PRIu64,
                 httpserverWebSocketOpcodeName(opcode), payload_len);
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

        if (available < header_len + 4 + (size_t) payload_len)
        {
            return true;
        }

        if ((opcode & 0x08U) != 0 && (! fin || payload_len > 125U))
        {
            LOGE("HttpServer: invalid websocket control frame opcode=%s fin=%s payload_len=%" PRIu64,
                 httpserverWebSocketOpcodeName(opcode), fin ? "true" : "false", payload_len);
            return false;
        }

        if (payload_len > UINT32_MAX)
        {
            LOGE("HttpServer: websocket frame exceeds buffer limits opcode=%s payload_len=%" PRIu64,
                 httpserverWebSocketOpcodeName(opcode), payload_len);
            return false;
        }

        sbuf_t *discard_header = bufferstreamReadExact(&ls->in_stream, header_len);
        lineReuseBuffer(l, discard_header);
        sbuf_t *mask_buf = bufferstreamReadExact(&ls->in_stream, 4);
        memoryCopy(mask_key, sbufGetRawPtr(mask_buf), 4);
        lineReuseBuffer(l, mask_buf);

        sbuf_t *payload = NULL;
        if (payload_len > 0)
        {
            payload = bufferstreamReadExact(&ls->in_stream, (size_t) payload_len);
            uint8_t *ptr = (uint8_t *) sbufGetMutablePtr(payload);
            for (uint32_t i = 0; i < sbufGetLength(payload); ++i)
            {
                ptr[i] ^= mask_key[i & 3U];
            }
        }

        if (opcode == kWebSocketOpcodePing)
        {
            if (httpserverVerboseEnabled(t))
            {
                LOGD("HttpServer: received websocket ping payload_len=%u", payload == NULL ? 0U : sbufGetLength(payload));
            }
            const void *pong_data = (payload == NULL) ? NULL : sbufGetRawPtr(payload);
            uint32_t    pong_len  = (payload == NULL) ? 0U : sbufGetLength(payload);
            bool        ok        = httpserverSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodePong, pong_data,
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
            if (httpserverVerboseEnabled(t))
            {
                LOGD("HttpServer: received websocket pong payload_len=%u", payload == NULL ? 0U : sbufGetLength(payload));
            }
            if (payload != NULL)
            {
                lineReuseBuffer(l, payload);
            }
            continue;
        }

        if (opcode == kWebSocketOpcodeClose)
        {
            if (httpserverVerboseEnabled(t))
            {
                LOGD("HttpServer: received websocket close payload_len=%u close_sent=%s",
                     payload == NULL ? 0U : sbufGetLength(payload), ls->websocket_close_sent ? "true" : "false");
            }

            if (! ls->websocket_close_sent)
            {
                const void *close_data = (payload == NULL) ? NULL : sbufGetRawPtr(payload);
                uint32_t    close_len  = (payload == NULL) ? 0U : sbufGetLength(payload);
                if (! httpserverSendWebSocketControlFrame(t, l, ls, kWebSocketOpcodeClose, close_data, close_len))
                {
                    if (payload != NULL)
                    {
                        lineReuseBuffer(l, payload);
                    }
                    LOGE("HttpServer: failed to send websocket close reply");
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
            LOGE("HttpServer: unsupported websocket opcode=%u", opcode);
            return false;
        }

        if (payload != NULL && ! httpserverForwardUpstreamPayload(t, l, ls, payload))
        {
            return false;
        }
    }
}

bool httpserverTransportFlushPendingDown(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ts->websocket_enabled && ! ls->websocket_active)
    {
        return true;
    }

    while (bufferqueueGetBufCount(&ls->pending_down) > 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_down);

        if (ts->websocket_enabled)
        {
            if (ls->runtime_proto == kHttpServerRuntimeHttp2 && ! ls->h2_response_headers_sent)
            {
                if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, false))
                {
                    lineReuseBuffer(l, buf);
                    return false;
                }
            }

            if (! httpserverTransportSendWebSocketData(t, l, ls, buf, kWebSocketOpcodeBinary))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpServerRuntimeUpgradedRaw)
        {
            tunnelPrevDownStreamPayload(t, l, buf);

            if (! lineIsAlive(l))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpServerRuntimeHttp2)
        {
            if (! ls->h2_response_headers_sent)
            {
                if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, false))
                {
                    lineReuseBuffer(l, buf);
                    return false;
                }
            }

            if (! httpserverTransportSendHttp2DataFrame(t, l, ls, buf, false))
            {
                return false;
            }
        }
        else if (ls->runtime_proto == kHttpServerRuntimeHttp1)
        {
            if (! ls->h1_response_headers_sent)
            {
                if (! httpserverTransportSendHttp1ResponseHeaders(t, l))
                {
                    lineReuseBuffer(l, buf);
                    return false;
                }
                ls->h1_response_headers_sent = true;
            }

            if (! httpserverTransportSendHttp1ChunkedPayload(t, l, buf))
            {
                return false;
            }
        }
        else
        {
            bufferqueuePushFront(&ls->pending_down, buf);
            return true;
        }
    }

    return true;
}

bool httpserverTransportDrainRawUp(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    while (! bufferstreamIsEmpty(&ls->in_stream))
    {
        sbuf_t *buf = bufferstreamIdealRead(&ls->in_stream);

        if (ls->next_finished)
        {
            lineReuseBuffer(l, buf);
            continue;
        }

        line_t *target = httpserverUpstreamTargetLine(ls, l);
        tunnelNextUpStreamPayload(t, target, buf);

        if (! lineIsAlive(l))
        {
            return false;
        }
    }

    return true;
}

static bool drainUpEvents(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    while (contextqueueLen(&ls->events_up) > 0)
    {
        context_t *ctx = contextqueuePop(&ls->events_up);

        lineLock(l);
        contextApplyOnNextTunnelU(ctx, t);
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

bool httpserverTransportFeedHttp2Input(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, sbuf_t *buf)
{
    uint32_t       len = sbufGetLength(buf);
    const uint8_t *ptr = (const uint8_t *) sbufGetRawPtr(buf);

    while (len > 0)
    {
        nghttp2_ssize ret = nghttp2_session_mem_recv2(ls->session, ptr, len);
        if (ret < 0)
        {
            LOGE("HttpServer: nghttp2_session_mem_recv2 failed (%zd)", ret);
            lineReuseBuffer(l, buf);
            return false;
        }

        if (ret == 0)
        {
            LOGE("HttpServer: nghttp2_session_mem_recv2 consumed 0 bytes");
            lineReuseBuffer(l, buf);
            return false;
        }

        ptr += (size_t) ret;
        len -= (uint32_t) ret;
    }

    lineReuseBuffer(l, buf);

    httpserver_tstate_t *ts = tunnelGetState(t);

    if (! sendNghttp2Outbound(t, l, ls))
    {
        return false;
    }

    if (ts->websocket_enabled)
    {
        if (ls->h2_stream_id > 0 && ! ls->websocket_active)
        {
            LOGE("HttpServer: websocket HTTP/2 handshake failed method=%s protocol=%s path=%s authority=%s version=%s origin=%s subprotocol=%s",
                 ls->websocket_h2_method_seen ? ls->websocket_h2_method : "<missing>",
                 ls->websocket_h2_protocol_seen ? ls->websocket_h2_protocol : "<missing>",
                 ls->websocket_h2_path_seen ? ls->websocket_h2_path : "<missing>",
                 ls->websocket_h2_authority_seen ? ls->websocket_h2_authority : "<missing>",
                 ls->websocket_h2_version_seen ? ls->websocket_h2_version : "<missing>",
                 ls->websocket_h2_origin_seen ? ls->websocket_h2_origin : "<none>",
                 ls->websocket_h2_subprotocol_seen ? ls->websocket_h2_subprotocol : "<none>");
            return false;
        }

        if (ls->websocket_active)
        {
            if (! ls->h2_response_headers_sent)
            {
                if (! httpserverTransportSubmitHttp2ResponseHeaders(t, l, ls, false))
                {
                    return false;
                }
            }

            if (! httpserverTransportDrainWebSocketUp(t, l, ls))
            {
                return false;
            }
        }
    }
    else if (! drainUpEvents(t, l, ls))
    {
        return false;
    }

    return true;
}

bool httpserverTransportDetectRuntimeProtocol(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (ls->runtime_proto != kHttpServerRuntimeUnknown)
    {
        return true;
    }

    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ts->version_mode == kHttpServerVersionModeHttp1)
    {
        ls->runtime_proto = kHttpServerRuntimeHttp1;
        return true;
    }

    if (ts->version_mode == kHttpServerVersionModeHttp2)
    {
        return httpserverTransportEnsureHttp2Session(t, l, ls);
    }

    size_t len = bufferstreamGetBufLen(&ls->in_stream);
    if (len == 0)
    {
        return true;
    }

    size_t probe_len = minSize(len, HTTP2_MAGIC_LEN);

    uint8_t probe_buf[HTTP2_MAGIC_LEN];
    bufferstreamViewBytesAt(&ls->in_stream, 0, probe_buf, probe_len);

    bool magic_prefix = (memoryCompare(probe_buf, HTTP2_MAGIC, probe_len) == 0);

    if (magic_prefix)
    {
        if (len < HTTP2_MAGIC_LEN)
        {
            return true;
        }

        if (ts->verbose)
        {
            LOGD("HttpServer: detected direct HTTP/2 client preface");
        }
        return httpserverTransportEnsureHttp2Session(t, l, ls);
    }

    if (ts->verbose)
    {
        LOGD("HttpServer: detected HTTP/1.1 request stream");
    }
    ls->runtime_proto = kHttpServerRuntimeHttp1;
    return true;
}

bool httpserverTransportHandleHttp1RequestHeaderPhase(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (ls->h1_headers_parsed)
    {
        return true;
    }

    if (bufferstreamGetBufLen(&ls->in_stream) > kHttpServerMaxHeaderBytes)
    {
        LOGE("HttpServer: request header exceeded maximum size");
        return false;
    }

    size_t header_end = 0;
    if (! httpserverBufferstreamFindDoubleCRLF(&ls->in_stream, &header_end))
    {
        return true;
    }

    sbuf_t *header_buf = bufferstreamReadExact(&ls->in_stream, header_end);

    char *header_text = memoryAllocate(header_end + 1);
    memoryCopy(header_text, sbufGetRawPtr(header_buf), header_end);
    header_text[header_end] = '\0';

    httpserver_h1_request_info_t info;
    bool                         parsed_ok = parseHttp1RequestHeaders(header_text, &info);

    lineReuseBuffer(l, header_buf);

    if (! parsed_ok)
    {
        memoryFree(header_text);
        LOGE("HttpServer: invalid HTTP/1.1 request headers");
        return false;
    }

    if (info.transfer_chunked && info.has_content_length)
    {
        memoryFree(header_text);
        LOGE("HttpServer: invalid HTTP/1.1 request (both Transfer-Encoding and Content-Length)");
        return false;
    }

    httpserver_tstate_t *ts = tunnelGetState(t);
    if (ts->websocket_enabled)
    {
        if (ts->verbose)
        {
            LOGD("HttpServer: parsed websocket HTTP/1.1 request method=%s path=%s host=%s origin=%s subprotocol=%s transfer-chunked=%s content-length=%" PRId64,
                 info.method, info.path, info.host, info.has_origin ? info.origin : "<none>",
                 info.has_sec_websocket_protocol ? info.sec_websocket_protocol : "<none>",
                 info.transfer_chunked ? "true" : "false", info.content_length);
        }

        if (! validateWebSocketHttp1Request(ts, &info))
        {
            memoryFree(header_text);
            return false;
        }

        ls->runtime_proto     = kHttpServerRuntimeHttp1;
        ls->h1_headers_parsed = true;
        ls->websocket_active  = true;

        if (! httpserverTransportSendHttp1WebSocketResponseHeaders(t, l, &info))
        {
            memoryFree(header_text);
            return false;
        }

        ls->h1_response_headers_sent = true;

        if (! httpserverTransportFlushPendingDown(t, l, ls))
        {
            memoryFree(header_text);
            return false;
        }

        memoryFree(header_text);
        return httpserverTransportDrainWebSocketUp(t, l, ls);
    }

    if (! validateHttp1Request(ts, &info))
    {
        memoryFree(header_text);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("HttpServer: parsed HTTP/1.1 request method=%s path=%s host=%s transfer-chunked=%s content-length=%s",
             info.method, info.path, info.host, info.transfer_chunked ? "true" : "false",
             info.has_content_length ? "true" : "false");
    }

    if (ts->version_mode == kHttpServerVersionModeBoth && ts->enable_upgrade && info.connection_upgrade)
    {
        bool request_has_body = info.transfer_chunked || (info.has_content_length && info.content_length > 0);

        if (httpserverUpgradeIsCustom(ts) && info.has_upgrade_header &&
            httpserverStringCaseContainsToken(info.upgrade_value, httpserverUpgradeProtocol(ts)) &&
            httpserverValidateRequiredHeaders(header_text, ts->upgrade_request_headers))
        {
            if (request_has_body)
            {
                LOGW("HttpServer: ignoring upgrade request protocol=%s because the original HTTP/1.1 request carries a body",
                     httpserverUpgradeProtocol(ts));
            }
            else
            {
                ls->runtime_proto     = kHttpServerRuntimeUpgradedRaw;
                ls->h1_headers_parsed = true;

                if (! httpserverTransportSendHttp1UpgradeResponseHeaders(t, l, httpserverUpgradeProtocol(ts)))
                {
                    memoryFree(header_text);
                    return false;
                }

                memoryFree(header_text);

                if (! httpserverTransportDrainRawUp(t, l, ls))
                {
                    return lineIsAlive(l) ? false : true;
                }

                if (! httpserverTransportFlushPendingDown(t, l, ls))
                {
                    return lineIsAlive(l) ? false : true;
                }

                return true;
            }
        }

        if (httpserverUpgradeIsH2C(ts) && info.connection_http2_settings && info.upgrade_h2c &&
            info.has_http2_settings &&
            httpserverValidateRequiredHeaders(header_text, ts->upgrade_request_headers))
        {
            if (request_has_body)
            {
                LOGW("HttpServer: ignoring h2c upgrade request that carries an HTTP/1.1 request body");
            }
            else
            {
                ls->h1_headers_parsed = true;
                if (! httpserverTransportApplyUpgradeSettingsAndOpenStream(t, l, ls, info.http2_settings, false))
                {
                    memoryFree(header_text);
                    return false;
                }

                if (! httpserverTransportSendHttp1UpgradeResponseHeaders(t, l, "h2c"))
                {
                    memoryFree(header_text);
                    return false;
                }

                memoryFree(header_text);

                if (! sendNghttp2Outbound(t, l, ls))
                {
                    return false;
                }

                while (! bufferstreamIsEmpty(&ls->in_stream))
                {
                    sbuf_t *leftover = bufferstreamIdealRead(&ls->in_stream);
                    if (! httpserverTransportFeedHttp2Input(t, l, ls, leftover))
                    {
                        return false;
                    }
                }

                return httpserverTransportFlushPendingDown(t, l, ls);
            }
        }
    }

    ls->runtime_proto      = kHttpServerRuntimeHttp1;
    ls->h1_headers_parsed  = true;
    ls->h1_request_chunked = info.transfer_chunked;

    if (info.transfer_chunked)
    {
        ls->h1_body_mode      = kHttpServerH1BodyChunked;
        ls->h1_chunk_expected = -1;
    }
    else if (info.has_content_length)
    {
        ls->h1_body_mode      = kHttpServerH1BodyContentLen;
        ls->h1_body_remaining = info.content_length;
        if (ls->h1_body_remaining == 0)
        {
            ls->h1_request_finished = true;
            if (! ts->full_duplex && ! ls->next_finished)
            {
                ls->next_finished = true;
                memoryFree(header_text);
                httpserverForwardUpstreamFinish(t, l, ls);
                return true;
            }
        }
    }
    else
    {
        ls->h1_body_mode = kHttpServerH1BodyNone;
        ls->h1_request_finished = true;
        if (! ts->full_duplex && ! ls->next_finished)
        {
            ls->next_finished = true;
            memoryFree(header_text);
            httpserverForwardUpstreamFinish(t, l, ls);
            return true;
        }
    }

    memoryFree(header_text);
    return httpserverTransportFlushPendingDown(t, l, ls);
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

bool httpserverTransportDrainHttp1ChunkedRequestBody(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    while (true)
    {
        if (ls->h1_chunk_expected < 0)
        {
            size_t line_end = 0;
            if (! httpserverBufferstreamFindCRLF(&ls->in_stream, &line_end))
            {
                return true;
            }

            sbuf_t *line_buf = bufferstreamReadExact(&ls->in_stream, line_end + 2);

            uint64_t chunk_len = 0;
            bool     ok        = parseChunkSizeLine(line_buf, &chunk_len);
            lineReuseBuffer(l, line_buf);

            if (! ok || chunk_len > (uint64_t) INT64_MAX)
            {
                LOGE("HttpServer: invalid chunked size line");
                return false;
            }

            ls->h1_chunk_expected = (int64_t) chunk_len;

            if (ls->h1_chunk_expected == 0)
            {
                while (true)
                {
                    size_t trailer_line_end = 0;
                    if (! httpserverBufferstreamFindCRLF(&ls->in_stream, &trailer_line_end))
                    {
                        return true;
                    }

                    sbuf_t *trailer_line = bufferstreamReadExact(&ls->in_stream, trailer_line_end + 2);
                    bool    done         = (trailer_line_end == 0);
                    lineReuseBuffer(l, trailer_line);

                    if (done)
                    {
                        if (! ls->next_finished)
                        {
                            ls->h1_request_finished = true;
                            if (! ts->full_duplex)
                            {
                                ls->next_finished = true;
                                httpserverForwardUpstreamFinish(t, l, ls);
                            }
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
                LOGE("HttpServer: invalid chunked frame tail");
                return false;
            }

            sbufSetLength(chunk_with_tail, (uint32_t) ls->h1_chunk_expected);

            if (! httpserverForwardUpstreamPayload(t, l, ls, chunk_with_tail))
            {
                return false;
            }

            ls->h1_chunk_expected = -1;
            continue;
        }
    }
}

bool httpserverTransportDrainHttp1RequestBody(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ls->h1_body_mode == kHttpServerH1BodyNone || ls->next_finished)
    {
        return true;
    }

    if (ls->h1_body_mode == kHttpServerH1BodyChunked)
    {
        return httpserverTransportDrainHttp1ChunkedRequestBody(t, l, ls);
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

        sbuf_t *buf = bufferstreamReadExact(&ls->in_stream, to_read);
        ls->h1_body_remaining -= (int64_t) to_read;

        if (! httpserverForwardUpstreamPayload(t, l, ls, buf))
        {
            return false;
        }
    }

    if (ls->h1_body_remaining == 0 && ! ls->next_finished)
    {
        ls->h1_request_finished = true;
        if (! ts->full_duplex)
        {
            ls->next_finished = true;
            httpserverForwardUpstreamFinish(t, l, ls);
        }
        return true;
    }

    return true;
}

static void httpserverTransportCloseDirections(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, bool close_next,
                                               bool close_prev)
{
    lineLock(l);

    bool send_next = close_next && ! ls->next_finished;
    bool send_prev = close_prev && ! ls->prev_finished;
    line_t *next_target = send_next ? httpserverUpstreamTargetLine(ls, l) : NULL;

    ls->next_finished = true;
    ls->prev_finished = true;

    httpserverLinestateDestroy(ls);

    if (next_target != NULL && lineIsAlive(next_target))
    {
        tunnelNextUpStreamFinish(t, next_target);
    }

    if (lineIsAlive(l) && send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}

void httpserverTransportCloseBothDirections(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserverTransportCloseDirections(t, l, ls, true, true);
}

void httpserverTransportCloseNextDirection(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserverTransportCloseDirections(t, l, ls, true, false);
}

void httpserverTransportClosePrevDirection(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    httpserverTransportCloseDirections(t, l, ls, false, true);
}
