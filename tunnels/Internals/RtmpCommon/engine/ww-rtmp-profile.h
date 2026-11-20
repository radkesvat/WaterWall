#ifndef WW_RTMP_PROFILE_H
#define WW_RTMP_PROFILE_H

#include "rtmp-client.h"
#include "rtmp-internal.h"
#include "rtmp-server.h"
#include "ww-rtmp-engine.h"

typedef enum
{
    kRtmpAwaitConnect,
    kRtmpAwaitCreate,
    kRtmpAwaitPublish,
    kRtmpPublishing,
    kRtmpActive,
    kRtmpClosed,
} ww_rtmp_phase_e;

struct ww_rtmp_engine
{
    union {
        rtmp_client_t *client;
        rtmp_server_t *server;
    } connection;
    struct rtmp_t             *protocol;
    ww_rtmp_engine_callbacks_t callbacks;
    void                      *context;
    char                       app[kRtmpMaxAppLength + 1];
    char                       stream[kRtmpMaxStreamLength + 1];
    uint64_t                   received_bytes;
    uint64_t                   acknowledged_bytes;
    uint32_t                   receive_interval;
    uint32_t                   advertised_window;
    uint32_t                   stream_id;
    ww_rtmp_phase_e            phase;
    bool                       is_server;
    bool                       started;
    bool                       stream_begin;
};

struct rtmp_t *ww_rtmp_client_profile(rtmp_client_t *client, ww_rtmp_engine_t *profile);
struct rtmp_t *ww_rtmp_server_profile(rtmp_server_t *server, ww_rtmp_engine_t *profile);

int  ww_rtmp_profile_input(struct rtmp_t *rtmp, const void *input, size_t size);
int  ww_rtmp_profile_output(struct rtmp_t *rtmp, ww_rtmp_output_e kind, const void *header, size_t header_size,
                            const void *payload, size_t payload_size);
int  ww_rtmp_profile_event(struct rtmp_t *rtmp, ww_rtmp_event_e event, uint32_t value, uint8_t detail);
int  ww_rtmp_profile_ready(struct rtmp_t *rtmp);
int  ww_rtmp_profile_closed(struct rtmp_t *rtmp);
int  ww_rtmp_profile_advertise(struct rtmp_t *rtmp);
int  ww_rtmp_profile_set_chunk_size(struct rtmp_t *rtmp);
int  ww_rtmp_profile_control(struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header, const uint8_t *data);
int  ww_rtmp_profile_user_control(struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header, const uint8_t *data);
bool ww_rtmp_profile_admit(const struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header);
bool ww_rtmp_profile_uint32(double value);

#endif
