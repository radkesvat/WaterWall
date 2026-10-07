#include "structure.h"

#include "loggers/network_logger.h"

sbuf_t *allocBufferForLength(line_t *l, uint32_t len)
{
    buffer_pool_t *pool = lineGetBufferPool(l);
    uint32_t       small_size = bufferpoolGetSmallBufferSize(pool);
    uint32_t       large_size = bufferpoolGetLargeBufferSize(pool);

    if (len <= small_size)
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (len <= large_size)
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    return sbufCreateWithPadding(len, bufferpoolGetLargeBufferPadding(pool));
}

size_t httpclientBuildHttp2Settings(const httpclient_tstate_t *ts,
                                    nghttp2_settings_entry     settings[kHttpClientHttp2SettingsMaxCount])
{
    settings[0] = (nghttp2_settings_entry) {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65536};
    settings[1] = (nghttp2_settings_entry) {NGHTTP2_SETTINGS_ENABLE_PUSH, 0};
    settings[2] = (nghttp2_settings_entry) {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, kHttpClientHttp2StreamWindow};
    settings[3] = (nghttp2_settings_entry) {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 262144};
    if (ts->websocket_enabled)
    {
        settings[4] = (nghttp2_settings_entry) {NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL, 1};
        return 5;
    }
    return 4;
}
