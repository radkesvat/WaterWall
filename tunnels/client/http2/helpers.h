#pragma once

typedef enum
{
    H2_SEND_MAGIC,
    H2_SEND_SETTINGS,
    H2_SEND_PING,
    H2_SEND_HEADERS,
    H2_SEND_DATA_FRAME_HD,
    H2_SEND_DATA,
    H2_SEND_DONE,

    H2_WANT_SEND,
    H2_WANT_RECV,

    H2_RECV_SETTINGS,
    H2_RECV_PING,
    H2_RECV_HEADERS,
    H2_RECV_DATA,
} http2_session_state;



static nghttp2_nv make_nv(const char* name, const char* value) {
    nghttp2_nv nv;
    nv.name = (uint8_t*)name;
    nv.value = (uint8_t*)value;
    nv.namelen = strlen(name);
    nv.valuelen = strlen(value);
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static nghttp2_nv make_nv2(const char* name, const char* value,
        int namelen, int valuelen) {
    nghttp2_nv nv;
    nv.name = (uint8_t*)name;
    nv.value = (uint8_t*)value;
    nv.namelen = namelen; nv.valuelen = valuelen;
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    return nv;
}

static void print_frame_hd(const nghttp2_frame_hd* hd) {
    printd("[frame] length=%d type=%x flags=%x stream_id=%d\n",
        (int)hd->length, (int)hd->type, (int)hd->flags, hd->stream_id);
}