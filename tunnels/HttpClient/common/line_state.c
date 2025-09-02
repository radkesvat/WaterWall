#include "structure.h"

#include "loggers/network_logger.h"

static void *httpclientNgh2CustomMemoryAllocate(size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryAllocate(size);
}

static void *httpclientNgh2CustomMemoryReAllocate(void *ptr, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryReAllocate(ptr, size);
}
static void *httpclientNgh2CustomMemoryCalloc(size_t n, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryCalloc(n, size);
}
static void httpclientNgh2CustomMemoryFree(void *ptr, void *mem_user_data)
{
    discard mem_user_data;
    memoryFree(ptr);
}

static void setupHttp2Stream(httpclient_lstate_t *con)
{

    char       authority_addr[320];
    nghttp2_nv nvs[15];
    int        nvlen = 0;

    nvs[nvlen++] = makeNV(":method", httpMethodStr(con->method));
    nvs[nvlen++] = makeNV(":path", con->path);
    nvs[nvlen++] = makeNV(":scheme", con->scheme);

    if (con->host_port == 0 || con->host_port == DEFAULT_HTTP_PORT || con->host_port == DEFAULT_HTTPS_PORT)
    {
        nvs[nvlen++] = (makeNV(":authority", con->host));
    }
    else
    {
        snprintf(authority_addr, sizeof(authority_addr), "%s:%d", con->host, con->host_port);
        nvs[nvlen++] = (makeNV(":authority", authority_addr));
    }

    // HTTP2_FLAG_END_STREAM;
    int flags = NGHTTP2_FLAG_END_HEADERS;

    if (con->content_type == kApplicationGrpc)
    {
        // flags = HTTP2_FLAG_NONE;
        nvs[nvlen++] = (makeNV("content-type", "application/grpc+proto"));
    }
    // todo (match chrome) this one is same as curl, but not same as chrome
    nvs[nvlen++] = makeNV("Accept", "*/*");
    // chrome:
    // "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");

    nvs[nvlen++] = makeNV("Accept-Language", "en,fa;q=0.9,zh-CN;q=0.8,zh;q=0.7");
    nvs[nvlen++] = makeNV("Cache-Control", "no-cache");
    nvs[nvlen++] = makeNV("Pragma", "no-cache");
    nvs[nvlen++] = makeNV("Sec-Ch-Ua", "Chromium\";v=\"122\", Not(A:Brand\";v=\"24\", \"Google Chrome\";v=\"122\"");
    nvs[nvlen++] = makeNV("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like "
                                        "Gecko) Chrome/122.0.0.0 Safari/537.36");
    nvs[nvlen++] = makeNV("Sec-Ch-Ua-Platform", "\"Windows\"");

    con->stream_id = nghttp2_submit_headers(con->session, flags, -1, NULL, &nvs[0], nvlen, con);

    assert(con->stream_id == 0);

    // memorySet(stream, 0, sizeof(http2_client_child_con_state_t));
    // stream->stream_id = nghttp2_submit_request2(con->session, NULL,  &nvs[0], nvlen, NULL,stream);
    // stream->stream_id          = nghttp2_submit_headers(con->session, flags, -1, NULL, &nvs[0], nvlen, stream);
    // stream->grpc_buffer_stream = bufferstreamCreate(getWorkerBufferPool(con->line));
    // stream->parent             = con->line;
    // stream->line               = child_line;
    // stream->tunnel             = con->tunnel;
    // addStraem(con, stream);
    // return stream;
}

void httpclientV2LinestateInitialize(httpclient_lstate_t *ls, tunnel_t *t, wid_t wid)
{
    static const int kBufferQueueCap = 4;

    httpclient_tstate_t *ts = tunnelGetState(t);

    *ls = (httpclient_lstate_t){.cq                  = contextqueueCreate(),
                                .cq_d                = contextqueueCreate(),
                                .bq                  = bufferqueueCreate(kBufferQueueCap),
                                .session             = NULL,
                                .tunnel              = t,
                                .line                = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid),
                                .path                = ts->path,
                                .host                = ts->host,
                                .scheme              = ts->scheme,
                                .method              = ts->content_type == kApplicationGrpc ? kHttpPost : kHttpGet,
                                .content_type        = ts->content_type,
                                .host_port           = ts->host_port,
                                .handshake_completed = false,
                                .init_sent           = false

    };

    nghttp2_mem mem = {.mem_user_data = NULL,
                       .malloc        = &httpclientNgh2CustomMemoryAllocate,
                       .free          = &httpclientNgh2CustomMemoryFree,
                       .calloc        = &httpclientNgh2CustomMemoryCalloc,
                       .realloc       = &httpclientNgh2CustomMemoryReAllocate};

    nghttp2_session_client_new3(&ls->session, ts->cbs, ls, ts->ngoptions, &mem);

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kDefaultHttp2MuxConcurrency},
                                         {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1U << 18)},
                                         {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 18)}

    };
    nghttp2_submit_settings(ls->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));
    setupHttp2Stream(ls);
}

void httpclientV2LinestateDestroy(httpclient_lstate_t *ls)
{
    nghttp2_session_del(ls->session);

    memoryZeroAligned32(ls, kLineStateSize);
}
