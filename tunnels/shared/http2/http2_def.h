#pragma once
#ifdef __cplusplus
extern "C"
{
#endif

#define HTTP2_MAGIC     "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_MAGIC_LEN 24

// length:3bytes + type:1byte + flags:1byte + stream_id:4bytes = 9bytes
#define HTTP2_FRAME_HDLEN 9

#define HTTP2_UPGRADE_RESPONSE                                                                                         \
    "HTTP/1.1 101 Switching Protocols\r\n"                                                                             \
    "Connection: Upgrade\r\n"                                                                                          \
    "Upgrade: h2c\r\n\r\n"

    typedef enum
    {
        kHttP2Data         = 0,
        kHttP2Headers      = 0x01,
        kHttP2Priority     = 0x02,
        kHttP2RstStream    = 0x03,
        kHttP2Settings     = 0x04,
        kHttP2PushPromise  = 0x05,
        kHttP2Ping         = 0x06,
        kHttP2Goaway       = 0x07,
        kHttP2WindowUpdate = 0x08,
        kHttP2Continuation = 0x09,
        kHttP2Altsvc       = 0x0a,
        kHttP2Origin       = 0x0c
    } http2_frame_type;

    typedef enum
    {
        kHttP2FlagNone       = 0,
        kHttP2FlagEndStream  = 0x01,
        kHttP2FlagEndHeaders = 0x04,
        kHttP2FlagPadded     = 0x08,
        kHttP2FlagPriority   = 0x20
    } http2_flag;

    typedef struct
    {
        int              length;
        http2_frame_type type;
        http2_flag       flags;
        int              stream_id;
    } http2_frame_hd;

    static inline void http2FrameHdPack(const http2_frame_hd *restrict hd, unsigned char *restrict buf)
    {
        // hton
        int            length    = hd->length;
        int            stream_id = hd->stream_id;
        unsigned char *p         = buf;
        *p++                     = (length >> 16) & 0xFF;
        *p++                     = (length >> 8) & 0xFF;
        *p++                     = length & 0xFF;
        *p++                     = (unsigned char) hd->type;
        *p++                     = (unsigned char) hd->flags;
        *p++                     = (stream_id >> 24) & 0xFF;
        *p++                     = (stream_id >> 16) & 0xFF;
        *p++                     = (stream_id >> 8) & 0xFF;
        *p++                     = stream_id & 0xFF;
    }

    static inline void http2FrameHdUnpack(const unsigned char *restrict buf, http2_frame_hd *restrict hd)
    {
        // ntoh
        const unsigned char *p = buf;
        hd->length             = *p++ << 16;
        hd->length += *p++ << 8;
        hd->length += *p++;

        hd->type  = (http2_frame_type) *p++;
        hd->flags = (http2_flag) *p++;

        hd->stream_id = *p++ << 24;
        hd->stream_id += *p++ << 16;
        hd->stream_id += *p++ << 8;
        hd->stream_id += *p++;
    }

#ifdef __cplusplus
}
#endif
