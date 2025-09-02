#include "structure.h"

#include "loggers/network_logger.h"

static void *httpserverNgh2CustomMemoryAllocate(size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryAllocate(size);
}

static void *httpserverNgh2CustomMemoryReAllocate(void *ptr, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryReAllocate(ptr, size);
}
static void *httpserverNgh2CustomMemoryCalloc(size_t n, size_t size, void *mem_user_data)
{
    discard mem_user_data;
    return memoryCalloc(n, size);
}
static void httpserverNgh2CustomMemoryFree(void *ptr, void *mem_user_data)
{
    discard mem_user_data;
    memoryFree(ptr);
}

static inline nghttp2_nv makeNV(const char *name, const char *value)
{
    nghttp2_nv nv;
    nv.name     = (uint8_t *) name;
    nv.value    = (uint8_t *) value;
    nv.namelen  = stringLength(name);
    nv.valuelen = stringLength(value);
    nv.flags    = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

void httpserverV2LinestateInitialize(httpserver_lstate_t *ls, tunnel_t *t, wid_t wid)
{

    httpserver_tstate_t *ts = tunnelGetState(t);

    *ls = (httpserver_lstate_t){.cq_u         = contextqueueCreate(),
                                .session      = NULL,
                                .tunnel       = t,
                                .line         = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid),
                                .content_type = kContentTypeNone,
                                .stream_id    = 0};

    nghttp2_mem mem = {.mem_user_data = NULL,
                       .malloc        = &httpserverNgh2CustomMemoryAllocate,
                       .free          = &httpserverNgh2CustomMemoryFree,
                       .calloc        = &httpserverNgh2CustomMemoryCalloc,
                       .realloc       = &httpserverNgh2CustomMemoryReAllocate};

    nghttp2_session_server_new3(&ls->session, ts->cbs, ls, ts->ngoptions, &mem);

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, kDefaultHttp2MuxConcurrency},
                                         {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (1U << 18)},
                                         {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 18)}

    };
    nghttp2_submit_settings(ls->session, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings));
}

void httpserverV2LinestateDestroy(httpserver_lstate_t *ls)
{
    nghttp2_session_del(ls->session);

    memoryZeroAligned32(ls, kLineStateSize);
}
