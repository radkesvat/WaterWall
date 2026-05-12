#include "structure.h"

#include "loggers/network_logger.h"
#include "pipe_tunnel.h"

#include <ctype.h>
#include <inttypes.h>

typedef struct httpserver_split_request_s
{
    char    method[32];
    char    path[2048];
    char    host[512];
    bool    transfer_chunked;
    bool    has_content_length;
    int64_t content_length;
} httpserver_split_request_t;

bool httpserverSplitIsEnabled(tunnel_t *t)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    return ts->h1_transport_mode == kHttpServerH1TransportSplit;
}

static bool splitHeaderNameEquals(const char *a, const char *b)
{
    return httpserverStringCaseEquals(a, b);
}

static bool splitParseContentLength(const char *value, int64_t *out)
{
    while (value != NULL && (*value == ' ' || *value == '\t'))
    {
        ++value;
    }
    if (value == NULL || *value == '\0')
    {
        return false;
    }

    char              *endp   = NULL;
    unsigned long long parsed = strtoull(value, &endp, 10);
    if (endp == value)
    {
        return false;
    }
    while (endp != NULL && (*endp == ' ' || *endp == '\t'))
    {
        ++endp;
    }
    if (endp == NULL || *endp != '\0' || parsed > (unsigned long long) INT64_MAX)
    {
        return false;
    }
    *out = (int64_t) parsed;
    return true;
}

static bool splitFindHeaderValue(const char *headers, const char *name, char *out, size_t out_cap)
{
    if (headers == NULL || name == NULL || out == NULL || out_cap == 0)
    {
        return false;
    }

    out[0]           = '\0';
    const char *line = strstr(headers, "\r\n");
    if (line == NULL)
    {
        return false;
    }
    line += 2;

    while (*line != '\0')
    {
        const char *next = strstr(line, "\r\n");
        if (next == NULL || next == line)
        {
            return false;
        }

        const char *colon = memchr(line, ':', (size_t) (next - line));
        if (colon != NULL)
        {
            size_t key_len = (size_t) (colon - line);
            char   key[128];
            if (key_len < sizeof(key))
            {
                memoryCopy(key, line, key_len);
                key[key_len] = '\0';

                if (splitHeaderNameEquals(key, name))
                {
                    const char *value = colon + 1;
                    while (value < next && (*value == ' ' || *value == '\t'))
                    {
                        ++value;
                    }
                    size_t value_len = (size_t) (next - value);
                    value_len        = min(value_len, out_cap - 1U);
                    memoryCopy(out, value, value_len);
                    out[value_len] = '\0';
                    return true;
                }
            }
        }

        line = next + 2;
    }

    return false;
}

static bool splitFindCookieValue(const char *headers, const char *name, char *out, size_t out_cap)
{
    char cookie[1024];
    if (! splitFindHeaderValue(headers, "Cookie", cookie, sizeof(cookie)))
    {
        return false;
    }

    size_t name_len = strlen(name);
    char  *saveptr  = NULL;
#ifdef COMPILER_MSVC
    char *part = strtok_s(cookie, ";", &saveptr);
#else
    char *part = strtok_r(cookie, ";", &saveptr);
#endif
    while (part != NULL)
    {
        while (*part == ' ' || *part == '\t')
        {
            ++part;
        }
        if (strncmp(part, name, name_len) == 0 && part[name_len] == '=')
        {
            stringCopyN(out, part + name_len + 1, out_cap);
            return true;
        }
#ifdef COMPILER_MSVC
        part = strtok_s(NULL, ";", &saveptr);
#else
        part = strtok_r(NULL, ";", &saveptr);
#endif
    }
    return false;
}

static size_t splitPathPartLen(const char *path)
{
    const char *q = strchr(path, '?');
    return q == NULL ? strlen(path) : (size_t) (q - path);
}

static bool splitPathTemplateMatches(const char *templ, const char *path)
{
    size_t ti   = 0;
    size_t pi   = 0;
    size_t tlen = splitPathPartLen(templ);
    size_t plen = splitPathPartLen(path);

    while (ti < tlen)
    {
        if (ti + 4 <= tlen && strncmp(templ + ti, "{id}", 4) == 0)
        {
            ti += 4;
        }
        else if (ti + 11 <= tlen && strncmp(templ + ti, "{direction}", 11) == 0)
        {
            ti += 11;
        }
        else if (ti + 7 <= tlen && strncmp(templ + ti, "{cache}", 7) == 0)
        {
            ti += 7;
        }
        else if (ti + 7 <= tlen && strncmp(templ + ti, "{token}", 7) == 0)
        {
            ti += 7;
        }
        else
        {
            if (pi >= plen || templ[ti] != path[pi])
            {
                return false;
            }
            ++ti;
            ++pi;
            continue;
        }

        size_t literal_start = ti;
        while (ti < tlen && strncmp(templ + ti, "{id}", 4) != 0 && strncmp(templ + ti, "{direction}", 11) != 0 &&
               strncmp(templ + ti, "{cache}", 7) != 0 && strncmp(templ + ti, "{token}", 7) != 0)
        {
            ++ti;
        }
        size_t literal_len = ti - literal_start;
        if (literal_len == 0)
        {
            if (ti >= tlen)
            {
                pi = plen;
            }
            continue;
        }

        bool found = false;
        while (pi + literal_len <= plen)
        {
            if (strncmp(path + pi, templ + literal_start, literal_len) == 0)
            {
                found = true;
                break;
            }
            ++pi;
        }
        if (! found)
        {
            return false;
        }
    }

    return pi == plen;
}

static bool splitQueryValue(const char *path, const char *name, char *out, size_t out_cap)
{
    const char *q = strchr(path, '?');
    if (q == NULL)
    {
        return false;
    }
    ++q;

    size_t name_len = strlen(name);
    while (*q != '\0')
    {
        const char *end = strchr(q, '&');
        if (end == NULL)
        {
            end = q + strlen(q);
        }
        const char *eq = memchr(q, '=', (size_t) (end - q));
        if (eq != NULL && (size_t) (eq - q) == name_len && strncmp(q, name, name_len) == 0)
        {
            size_t value_len = (size_t) (end - eq - 1);
            value_len        = min(value_len, out_cap - 1U);
            memoryCopy(out, eq + 1, value_len);
            out[value_len] = '\0';
            return true;
        }
        q = *end == '&' ? end + 1 : end;
    }
    return false;
}

static bool splitExtractPathVar(const char *templ, const char *path, const char *token, char *out, size_t out_cap)
{
    const char *pos = strstr(templ, token);
    if (pos == NULL)
    {
        return false;
    }

    size_t prefix_len = (size_t) (pos - templ);
    if (strncmp(templ, path, prefix_len) != 0)
    {
        return false;
    }

    const char *value_start      = path + prefix_len;
    const char *suffix           = pos + strlen(token);
    size_t      suffix_len       = splitPathPartLen(suffix);
    const char *next_placeholder = strstr(suffix, "{");
    if (next_placeholder != NULL && (size_t) (next_placeholder - suffix) < suffix_len)
    {
        suffix_len = (size_t) (next_placeholder - suffix);
    }

    const char *path_end  = path + splitPathPartLen(path);
    const char *value_end = path_end;
    if (suffix_len > 0)
    {
        const char *found = NULL;
        for (const char *p = value_start; p + suffix_len <= path_end; ++p)
        {
            if (strncmp(p, suffix, suffix_len) == 0)
            {
                found = p;
                break;
            }
        }
        if (found == NULL)
        {
            return false;
        }
        value_end = found;
    }

    size_t value_len = (size_t) (value_end - value_start);
    if (value_len == 0)
    {
        return false;
    }
    value_len = min(value_len, out_cap - 1U);
    memoryCopy(out, value_start, value_len);
    out[value_len] = '\0';
    return true;
}

static bool splitParseRequest(const char *headers, httpserver_split_request_t *info)
{
    *info = (httpserver_split_request_t) {0};

    char *tmp      = stringDuplicate(headers);
    char *line_end = strstr(tmp, "\r\n");
    if (line_end == NULL)
    {
        memoryFree(tmp);
        return false;
    }
    *line_end = '\0';

    if (sscanf(tmp, "%31s %2047s HTTP/%*d.%*d", info->method, info->path) != 2)
    {
        memoryFree(tmp);
        return false;
    }
    memoryFree(tmp);

    splitFindHeaderValue(headers, "Host", info->host, sizeof(info->host));

    char value[256];
    if (splitFindHeaderValue(headers, "Transfer-Encoding", value, sizeof(value)) &&
        httpserverStringCaseContainsToken(value, "chunked"))
    {
        info->transfer_chunked = true;
    }

    if (splitFindHeaderValue(headers, "Content-Length", value, sizeof(value)))
    {
        if (! splitParseContentLength(value, &info->content_length))
        {
            return false;
        }
        info->has_content_length = true;
    }

    return ! (info->transfer_chunked && info->has_content_length);
}

static bool splitExtractPlacedValue(httpserver_split_placement_t placement, const char *name, const char *path,
                                    const char *headers, const char *path_template, const char *path_token, char *out,
                                    size_t out_cap)
{
    switch (placement)
    {
    case kHttpServerSplitPlacementQuery:
        return splitQueryValue(path, name, out, out_cap);
    case kHttpServerSplitPlacementHeader:
        return splitFindHeaderValue(headers, name, out, out_cap);
    case kHttpServerSplitPlacementCookie:
        return splitFindCookieValue(headers, name, out, out_cap);
    case kHttpServerSplitPlacementPath:
        return splitExtractPathVar(path_template, path, path_token, out, out_cap);
    }
    return false;
}

static bool splitHostMatches(const char *expected, const char *actual)
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
    if (strlen(expected) != host_len)
    {
        return false;
    }
    for (size_t i = 0; i < host_len; ++i)
    {
        if ((char) tolower((unsigned char) expected[i]) != (char) tolower((unsigned char) actual[i]))
        {
            return false;
        }
    }
    return true;
}

static httpserver_split_role_t splitDetermineRole(httpserver_tstate_t *ts, const httpserver_split_request_t *info,
                                                  const char *headers)
{
    char direction[128];
    if (ts->split_direction_placement == kHttpServerSplitPlacementPath)
    {
        if (splitExtractPathVar(ts->split_upload_path, info->path, "{direction}", direction, sizeof(direction)) &&
            httpserverStringCaseEquals(direction, ts->split_upload_value))
        {
            return kHttpServerSplitRoleUpload;
        }
        if (splitExtractPathVar(ts->split_download_path, info->path, "{direction}", direction, sizeof(direction)) &&
            httpserverStringCaseEquals(direction, ts->split_download_value))
        {
            return kHttpServerSplitRoleDownload;
        }
    }
    else if (splitExtractPlacedValue(ts->split_direction_placement,
                                     ts->split_direction_name,
                                     info->path,
                                     headers,
                                     ts->split_upload_path,
                                     "{direction}",
                                     direction,
                                     sizeof(direction)))
    {
        if (httpserverStringCaseEquals(direction, ts->split_upload_value))
        {
            return kHttpServerSplitRoleUpload;
        }
        if (httpserverStringCaseEquals(direction, ts->split_download_value))
        {
            return kHttpServerSplitRoleDownload;
        }
    }

    bool upload_match   = httpserverStringCaseEquals(info->method, ts->split_upload_method) &&
                          splitPathTemplateMatches(ts->split_upload_path, info->path);
    bool download_match = httpserverStringCaseEquals(info->method, ts->split_download_method) &&
                          splitPathTemplateMatches(ts->split_download_path, info->path);
    if (upload_match && ! download_match)
    {
        return kHttpServerSplitRoleUpload;
    }
    if (download_match && ! upload_match)
    {
        return kHttpServerSplitRoleDownload;
    }
    return kHttpServerSplitRoleUnknown;
}

static bool splitValidateRequest(tunnel_t *t, line_t *l, const httpserver_split_request_t *info, const char *headers,
                                 httpserver_split_role_t role, hash_t *hash_out)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    const char *method = role == kHttpServerSplitRoleDownload ? ts->split_download_method : ts->split_upload_method;
    const char *path_template = role == kHttpServerSplitRoleDownload ? ts->split_download_path : ts->split_upload_path;

    if (! httpserverStringCaseEquals(info->method, method) || ! splitPathTemplateMatches(path_template, info->path))
    {
        LOGW("HttpServer: split HTTP/1.1 request mismatch method=%s path=%s", info->method, info->path);
        return false;
    }

    if (! splitHostMatches(ts->expected_host, info->host))
    {
        LOGW("HttpServer: split HTTP/1.1 host mismatch expected=%s got=%s", ts->expected_host, info->host);
        return false;
    }

    if (ts->split_token != NULL)
    {
        char token[256];
        if (! splitExtractPlacedValue(ts->split_token_placement,
                                      ts->split_token_name,
                                      info->path,
                                      headers,
                                      path_template,
                                      "{token}",
                                      token,
                                      sizeof(token)) ||
            stringCompare(token, ts->split_token) != 0)
        {
            LOGW("HttpServer: split HTTP/1.1 token mismatch");
            return false;
        }
    }

    char id[256];
    if (! splitExtractPlacedValue(
            ts->split_id_placement, ts->split_id_name, info->path, headers, path_template, "{id}", id, sizeof(id)))
    {
        LOGW("HttpServer: split HTTP/1.1 request has no pairing identifier");
        return false;
    }

    *hash_out = calcHashBytes(id, strlen(id));
    discard l;
    return true;
}

static bool splitFindCounterpartWid(tunnel_t *t, httpserver_split_role_t role, hash_t hash, wid_t *wid_out)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    if (role == kHttpServerSplitRoleUpload)
    {
        mutexLock(&ts->split_download_map_mutex);
        hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_download_map, hash);
        if (it.ref != hmap_httpserver_split_t_end(&ts->split_download_map).ref)
        {
            httpserver_lstate_t *dls = it.ref->second;
            if (dls->split_download_line != NULL)
            {
                *wid_out = lineGetWID(dls->split_download_line);
                mutexUnlock(&ts->split_download_map_mutex);
                return true;
            }
        }
        mutexUnlock(&ts->split_download_map_mutex);
        return false;
    }

    if (role == kHttpServerSplitRoleDownload)
    {
        mutexLock(&ts->split_upload_map_mutex);
        hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_upload_map, hash);
        if (it.ref != hmap_httpserver_split_t_end(&ts->split_upload_map).ref)
        {
            httpserver_lstate_t *uls = it.ref->second;
            if (uls->split_upload_line != NULL)
            {
                *wid_out = lineGetWID(uls->split_upload_line);
                mutexUnlock(&ts->split_upload_map_mutex);
                return true;
            }
        }
        mutexUnlock(&ts->split_upload_map_mutex);
    }

    return false;
}

static bool splitPipeCurrentLineToWorker(tunnel_t *t, line_t *l, httpserver_lstate_t *ls, wid_t target_wid)
{
    sbuf_t *raw = bufferstreamFullRead(&ls->in_stream);
    httpserverLinestateDestroy(ls);

    if (raw == NULL)
    {
        return false;
    }

    if (pipeTo(t, l, target_wid))
    {
        tunnel_t *prev_tunnel = t->prev;
        tunnelUpStreamPayload(prev_tunnel, l, raw);
        return true;
    }

    lineReuseBuffer(l, raw);
    tunnelPrevDownStreamFinish(t, l);
    return true;
}

static void splitRemoveFromMaps(tunnel_t *t, httpserver_lstate_t *ls)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    if (ls->split_hash == 0)
    {
        return;
    }

    if (ls->split_role == kHttpServerSplitRoleUpload)
    {
        mutexLock(&ts->split_upload_map_mutex);
        hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_upload_map, ls->split_hash);
        if (it.ref != hmap_httpserver_split_t_end(&ts->split_upload_map).ref)
        {
            hmap_httpserver_split_t_erase_at(&ts->split_upload_map, it);
        }
        mutexUnlock(&ts->split_upload_map_mutex);
    }
    else if (ls->split_role == kHttpServerSplitRoleDownload)
    {
        mutexLock(&ts->split_download_map_mutex);
        hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_download_map, ls->split_hash);
        if (it.ref != hmap_httpserver_split_t_end(&ts->split_download_map).ref)
        {
            hmap_httpserver_split_t_erase_at(&ts->split_download_map, it);
        }
        mutexUnlock(&ts->split_download_map_mutex);
    }
}

static void splitCloseTransport(tunnel_t *t, line_t *l, bool send_down_finish)
{
    if (l == NULL || ! lineIsAlive(l))
    {
        return;
    }
    httpserver_lstate_t *ls = lineGetState(l, t);
    splitRemoveFromMaps(t, ls);
    httpserverLinestateDestroy(ls);
    if (send_down_finish)
    {
        tunnelPrevDownStreamFinish(t, l);
    }
}

static void splitCloseMain(tunnel_t *t, line_t *main_line, bool send_next_finish)
{
    if (main_line == NULL || ! lineIsAlive(main_line))
    {
        return;
    }
    httpserver_lstate_t *main_ls = lineGetState(main_line, t);
    httpserverLinestateDestroy(main_ls);
    if (send_next_finish)
    {
        tunnelNextUpStreamFinish(t, main_line);
    }
    if (lineIsAlive(main_line))
    {
        lineDestroy(main_line);
    }
}

static void splitCloseFromTransport(tunnel_t *t, line_t *l, bool finish_sender)
{
    httpserver_lstate_t *ls            = lineGetState(l, t);
    line_t              *main_line     = ls->split_main_line;
    line_t              *upload_line   = ls->split_upload_line;
    line_t              *download_line = ls->split_download_line;

    if (download_line != NULL && download_line != l && lineIsAlive(download_line))
    {
        lineLock(download_line);
        httpserver_lstate_t *dls = lineGetState(download_line, t);
        if (dls->h1_response_headers_sent && ! dls->fin_sent)
        {
            dls->fin_sent = true;
            (void) httpserverTransportSendHttp1FinalChunk(t, download_line);
        }
        splitCloseTransport(t, download_line, true);
        lineUnlock(download_line);
    }

    if (upload_line != NULL && upload_line != l && lineIsAlive(upload_line))
    {
        lineLock(upload_line);
        splitCloseTransport(t, upload_line, true);
        lineUnlock(upload_line);
    }

    if (main_line != NULL && lineIsAlive(main_line))
    {
        lineLock(main_line);
        splitCloseMain(t, main_line, true);
        lineUnlock(main_line);
    }

    splitCloseTransport(t, l, finish_sender);
}

static bool splitPair(tunnel_t *t, line_t *upload_line, line_t *download_line)
{
    httpserver_lstate_t *uls = lineGetState(upload_line, t);
    httpserver_lstate_t *dls = lineGetState(download_line, t);

    line_t              *main_line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(upload_line));
    httpserver_lstate_t *mls       = lineGetState(main_line, t);
    httpserverLinestateInitialize(mls, t, main_line);

    mls->split_role          = kHttpServerSplitRoleMain;
    mls->split_main_line     = main_line;
    mls->split_upload_line   = upload_line;
    mls->split_download_line = download_line;
    mls->runtime_proto       = kHttpServerRuntimeHttp1;

    uls->split_main_line     = main_line;
    uls->split_upload_line   = upload_line;
    uls->split_download_line = download_line;
    dls->split_main_line     = main_line;
    dls->split_upload_line   = upload_line;
    dls->split_download_line = download_line;

    if (! withLineLocked(main_line, tunnelNextUpStreamInit, t))
    {
        return false;
    }

    return httpserverTransportDrainHttp1RequestBody(t, upload_line, uls);
}

static bool splitInsertOrPairUpload(tunnel_t *t, line_t *l)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    httpserver_lstate_t *ls = lineGetState(l, t);

    mutexLock(&ts->split_download_map_mutex);
    hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_download_map, ls->split_hash);
    if (it.ref != hmap_httpserver_split_t_end(&ts->split_download_map).ref)
    {
        httpserver_lstate_t *dls           = it.ref->second;
        line_t              *download_line = dls->split_download_line;
        hmap_httpserver_split_t_erase_at(&ts->split_download_map, it);
        mutexUnlock(&ts->split_download_map_mutex);
        bool ok = lineGetWID(download_line) == lineGetWID(l) && splitPair(t, l, download_line);
        if (! ok && download_line != NULL && lineIsAlive(download_line))
        {
            lineLock(download_line);
            splitCloseTransport(t, download_line, true);
            lineUnlock(download_line);
        }
        return ok;
    }
    mutexUnlock(&ts->split_download_map_mutex);

    mutexLock(&ts->split_upload_map_mutex);
    bool inserted = hmap_httpserver_split_t_insert(&ts->split_upload_map, ls->split_hash, ls).inserted;
    mutexUnlock(&ts->split_upload_map_mutex);
    if (! inserted)
    {
        LOGW("HttpServer: duplicate split upload request closed");
        return false;
    }
    return true;
}

static bool splitInsertOrPairDownload(tunnel_t *t, line_t *l)
{
    httpserver_tstate_t *ts = tunnelGetState(t);
    httpserver_lstate_t *ls = lineGetState(l, t);

    if (! ls->h1_response_headers_sent)
    {
        if (! httpserverTransportSendHttp1ResponseHeaders(t, l))
        {
            return false;
        }
        ls->h1_response_headers_sent = true;
    }

    mutexLock(&ts->split_upload_map_mutex);
    hmap_httpserver_split_t_iter it = hmap_httpserver_split_t_find(&ts->split_upload_map, ls->split_hash);
    if (it.ref != hmap_httpserver_split_t_end(&ts->split_upload_map).ref)
    {
        httpserver_lstate_t *uls         = it.ref->second;
        line_t              *upload_line = uls->split_upload_line;
        hmap_httpserver_split_t_erase_at(&ts->split_upload_map, it);
        mutexUnlock(&ts->split_upload_map_mutex);
        bool ok = lineGetWID(upload_line) == lineGetWID(l) && splitPair(t, upload_line, l);
        if (! ok && upload_line != NULL && lineIsAlive(upload_line))
        {
            lineLock(upload_line);
            splitCloseTransport(t, upload_line, true);
            lineUnlock(upload_line);
        }
        return ok;
    }
    mutexUnlock(&ts->split_upload_map_mutex);

    mutexLock(&ts->split_download_map_mutex);
    bool inserted = hmap_httpserver_split_t_insert(&ts->split_download_map, ls->split_hash, ls).inserted;
    mutexUnlock(&ts->split_download_map_mutex);
    if (! inserted)
    {
        LOGW("HttpServer: duplicate split download request closed");
        return false;
    }
    return true;
}

static bool splitHandleHeaders(tunnel_t *t, line_t *l, httpserver_lstate_t *ls)
{
    if (ls->h1_headers_parsed)
    {
        return true;
    }

    if (bufferstreamGetBufLen(&ls->in_stream) > kHttpServerMaxHeaderBytes)
    {
        LOGE("HttpServer: split HTTP/1.1 request header exceeded maximum size");
        return false;
    }

    size_t header_end = 0;
    if (! httpserverBufferstreamFindDoubleCRLF(&ls->in_stream, &header_end))
    {
        return true;
    }

    char *header_text = memoryAllocate(header_end + 1);
    bufferstreamViewBytesAt(&ls->in_stream, 0, (uint8_t *) header_text, header_end);
    header_text[header_end] = '\0';

    httpserver_split_request_t info;
    if (! splitParseRequest(header_text, &info))
    {
        LOGE("HttpServer: invalid split HTTP/1.1 request headers");
        memoryFree(header_text);
        return false;
    }

    httpserver_split_role_t role = splitDetermineRole(tunnelGetState(t), &info, header_text);
    if (role != kHttpServerSplitRoleUpload && role != kHttpServerSplitRoleDownload)
    {
        LOGW("HttpServer: split HTTP/1.1 request direction is unknown");
        memoryFree(header_text);
        return false;
    }

    hash_t hash = 0;
    if (! splitValidateRequest(t, l, &info, header_text, role, &hash))
    {
        memoryFree(header_text);
        return false;
    }

    wid_t counterpart_wid = 0;
    if (splitFindCounterpartWid(t, role, hash, &counterpart_wid) && counterpart_wid != lineGetWID(l))
    {
        memoryFree(header_text);
        return splitPipeCurrentLineToWorker(t, l, ls, counterpart_wid);
    }

    sbuf_t *header_buf = bufferstreamReadExact(&ls->in_stream, header_end);
    lineReuseBuffer(l, header_buf);

    ls->runtime_proto     = kHttpServerRuntimeHttp1;
    ls->h1_headers_parsed = true;
    ls->split_role        = role;
    ls->split_hash        = hash;

    if (role == kHttpServerSplitRoleUpload)
    {
        ls->split_upload_line = l;
        if (info.transfer_chunked)
        {
            ls->h1_body_mode      = kHttpServerH1BodyChunked;
            ls->h1_chunk_expected = -1;
        }
        else if (info.has_content_length)
        {
            ls->h1_body_mode      = kHttpServerH1BodyContentLen;
            ls->h1_body_remaining = info.content_length;
        }
        else
        {
            ls->h1_body_mode        = kHttpServerH1BodyNone;
            ls->h1_request_finished = true;
        }
    }
    else
    {
        if (info.transfer_chunked || (info.has_content_length && info.content_length > 0))
        {
            LOGW("HttpServer: split download request must not carry a body");
            memoryFree(header_text);
            return false;
        }
        ls->split_download_line = l;
        ls->h1_body_mode        = kHttpServerH1BodyNone;
        ls->h1_request_finished = true;
    }

    memoryFree(header_text);

    if (role == kHttpServerSplitRoleUpload)
    {
        return splitInsertOrPairUpload(t, l);
    }
    return splitInsertOrPairDownload(t, l);
}

void httpserverSplitUpStreamInit(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    httpserverLinestateInitialize(ls, t, l);
    ls->runtime_proto = kHttpServerRuntimeHttp1;
    ls->split_role    = kHttpServerSplitRoleUnknown;
}

void httpserverSplitUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *ls = lineGetState(l, t);
    lineLock(l);

    bufferstreamPush(&ls->in_stream, buf);

    bool ok = splitHandleHeaders(t, l, ls);
    if (ok && lineIsAlive(l) && ls->h1_headers_parsed && ls->split_role == kHttpServerSplitRoleUpload)
    {
        if (ls->split_main_line != NULL)
        {
            ok = httpserverTransportDrainHttp1RequestBody(t, l, ls);
        }
        else if (bufferstreamGetBufLen(&ls->in_stream) > kHttpServerSplitMaxBuffering)
        {
            httpserver_tstate_t *ts = tunnelGetState(t);
            if (! ts->no_split_upload_buffering_limit) // probably running test cases
            {
                LOGW("HttpServer: split upload buffering exceeded limit before download paired");
                ok = false;
            }
        }
    }

    if (! ok && lineIsAlive(l))
    {
        splitCloseFromTransport(t, l, true);
    }

    lineUnlock(l);
}

void httpserverSplitUpStreamFinish(tunnel_t *t, line_t *l)
{
    splitCloseFromTransport(t, l, false);
}

void httpserverSplitDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    httpserver_lstate_t *mls           = lineGetState(l, t);
    line_t              *download_line = mls->split_download_line;
    if (download_line == NULL || ! lineIsAlive(download_line))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    lineLock(download_line);
    httpserver_lstate_t *dls = lineGetState(download_line, t);
    if (! dls->h1_response_headers_sent)
    {
        if (! httpserverTransportSendHttp1ResponseHeaders(t, download_line))
        {
            lineReuseBuffer(l, buf);
            lineUnlock(download_line);
            splitCloseFromTransport(t, download_line, true);
            return;
        }
        dls->h1_response_headers_sent = true;
    }

    if (! httpserverTransportSendHttp1ChunkedPayload(t, download_line, buf))
    {
        lineUnlock(download_line);
        splitCloseFromTransport(t, download_line, true);
        return;
    }
    lineUnlock(download_line);
}

void httpserverSplitDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpserver_lstate_t *mls           = lineGetState(l, t);
    line_t              *upload_line   = mls->split_upload_line;
    line_t              *download_line = mls->split_download_line;

    if (download_line != NULL && lineIsAlive(download_line))
    {
        lineLock(download_line);
        httpserver_lstate_t *dls = lineGetState(download_line, t);
        if (! dls->h1_response_headers_sent)
        {
            (void) httpserverTransportSendHttp1ResponseHeaders(t, download_line);
            dls->h1_response_headers_sent = true;
        }
        if (! dls->fin_sent)
        {
            dls->fin_sent = true;
            (void) httpserverTransportSendHttp1FinalChunk(t, download_line);
        }
        splitCloseTransport(t, download_line, true);
        lineUnlock(download_line);
    }

    if (upload_line != NULL && lineIsAlive(upload_line))
    {
        lineLock(upload_line);
        splitCloseTransport(t, upload_line, true);
        lineUnlock(upload_line);
    }

    splitCloseMain(t, l, false);
}
