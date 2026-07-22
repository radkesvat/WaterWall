#include <nghttp2/nghttp2.h>

#include "wlibc.h"

enum
{
    kPayloadLen      = 48 * 1024,
    kLargeRecvFloor = 32 * 1024
};

typedef struct client_data_s
{
    size_t offset;
} client_data_t;

typedef struct server_data_s
{
    size_t received;
} server_data_t;

static void require(int condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static uint8_t pattern_byte(size_t offset)
{
    return (uint8_t) ((offset * 131U + 17U) & 0xffU);
}

static ssize_t read_payload_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
                                     uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    (void) session;
    (void) stream_id;
    (void) user_data;

    client_data_t *client_data = (client_data_t *) source->ptr;
    size_t         remaining   = kPayloadLen - client_data->offset;
    size_t         nread       = remaining < length ? remaining : length;

    for (size_t i = 0; i < nread; ++i)
    {
        buf[i] = pattern_byte(client_data->offset + i);
    }

    client_data->offset += nread;
    if (client_data->offset == kPayloadLen)
    {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    return (ssize_t) nread;
}

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                       const uint8_t *data, size_t len, void *user_data)
{
    (void) session;
    (void) flags;
    (void) stream_id;

    server_data_t *server_data = (server_data_t *) user_data;

    for (size_t i = 0; i < len; ++i)
    {
        if (data[i] != pattern_byte(server_data->received + i))
        {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    server_data->received += len;
    return 0;
}

static void append_wire(uint8_t **wire, size_t *wire_len, size_t *wire_cap, const uint8_t *data, size_t data_len)
{
    if (*wire_len + data_len > *wire_cap)
    {
        size_t new_cap = *wire_cap == 0 ? 65536U : *wire_cap;
        while (*wire_len + data_len > new_cap)
        {
            new_cap *= 2U;
        }

        uint8_t *grown = realloc(*wire, new_cap);
        require(grown != NULL, "realloc failed while collecting nghttp2 output");
        *wire     = grown;
        *wire_cap = new_cap;
    }

    memcpy(*wire + *wire_len, data, data_len);
    *wire_len += data_len;
}

int main(void)
{
    nghttp2_session_callbacks *client_callbacks = NULL;
    nghttp2_session_callbacks *server_callbacks = NULL;
    nghttp2_session           *client           = NULL;
    nghttp2_session           *server           = NULL;

    require(nghttp2_session_callbacks_new(&client_callbacks) == 0, "client callbacks allocation failed");
    require(nghttp2_session_callbacks_new(&server_callbacks) == 0, "server callbacks allocation failed");
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(server_callbacks, on_data_chunk_recv_callback);

    client_data_t client_data = {.offset = 0};
    server_data_t server_data = {.received = 0};

    require(nghttp2_session_client_new(&client, client_callbacks, &client_data) == 0, "client session allocation failed");
    require(nghttp2_session_server_new(&server, server_callbacks, &server_data) == 0, "server session allocation failed");

    require(nghttp2_submit_settings(client, NGHTTP2_FLAG_NONE, NULL, 0) == 0, "client settings submit failed");

    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/large", 5, 6, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
    };

    nghttp2_data_provider provider = {
        .source        = {.ptr = &client_data},
        .read_callback = read_payload_callback,
    };
    int32_t stream_id = nghttp2_submit_request(client, NULL, headers, sizeof(headers) / sizeof(headers[0]), &provider,
                                               NULL);
    require(stream_id > 0, "request submit failed");

    uint8_t *wire     = NULL;
    size_t   wire_len = 0;
    size_t   wire_cap = 0;

    while (1)
    {
        const uint8_t *data = NULL;
        nghttp2_ssize  len  = nghttp2_session_mem_send2(client, &data);
        require(len >= 0, "client mem_send failed");
        if (len == 0)
        {
            break;
        }
        append_wire(&wire, &wire_len, &wire_cap, data, (size_t) len);
    }

    require(wire_len > kLargeRecvFloor, "generated HTTP/2 input did not exceed 32 KiB");

    nghttp2_ssize consumed = nghttp2_session_mem_recv2(server, wire, wire_len);
    require(consumed == (nghttp2_ssize) wire_len, "server did not consume the full large input buffer");
    require(server_data.received == kPayloadLen, "server did not receive the full DATA payload");

    free(wire);
    nghttp2_session_del(client);
    nghttp2_session_del(server);
    nghttp2_session_callbacks_del(client_callbacks);
    nghttp2_session_callbacks_del(server_callbacks);

    return 0;
}
