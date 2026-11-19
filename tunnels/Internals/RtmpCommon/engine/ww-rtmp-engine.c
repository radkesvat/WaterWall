#include "ww-rtmp-profile.h"

#include "rtmp-control-message.h"
#include "rtmp-event.h"
#include "rtmp-msgtypeid.h"
#include "rtmp-util.h"
#include "wmem.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

static const int kRtmpPublishMode = 0;

static bool textFits(const char *value, size_t limit)
{
    return value && *value && strlen(value) <= limit;
}

ww_rtmp_engine_t *wwRtmpEngineCreate(bool server, const char *app, const char *stream, const char *tc_url,
                                     const ww_rtmp_engine_callbacks_t *callbacks, void *context)
{
    assert(callbacks && callbacks->send && callbacks->data && callbacks->event);
    if (! textFits(app, kRtmpMaxAppLength) || ! textFits(stream, kRtmpMaxStreamLength) ||
        (! server && ! textFits(tc_url, kRtmpMaxUrlLength)))
        return NULL;

    ww_rtmp_engine_t *engine = memoryAllocateZero(sizeof(*engine));
    engine->callbacks        = *callbacks;
    engine->context          = context;
    engine->phase            = kRtmpAwaitConnect;
    engine->is_server        = server;
    engine->started          = server;
    memcpy(engine->app, app, strlen(app) + 1);
    memcpy(engine->stream, stream, strlen(stream) + 1);

    if (server)
    {
        const struct rtmp_server_handler_t handler = {0};
        engine->connection.server                  = rtmp_server_create(NULL, &handler);
        engine->protocol                           = ww_rtmp_server_profile(engine->connection.server, engine);
    }
    else
    {
        const struct rtmp_client_handler_t handler = {0};
        engine->connection.client                  = rtmp_client_create(app, stream, tc_url, NULL, &handler);
        engine->protocol                           = ww_rtmp_client_profile(engine->connection.client, engine);
    }
    return engine;
}

void wwRtmpEngineDestroy(ww_rtmp_engine_t *engine)
{
    if (engine->is_server)
        rtmp_server_destroy(engine->connection.server);
    else
        rtmp_client_destroy(engine->connection.client);
    memoryFree(engine);
}

int wwRtmpEngineStart(ww_rtmp_engine_t *engine)
{
    assert(! engine->is_server && ! engine->started);
    engine->started = true;
    return rtmp_client_start(engine->connection.client, kRtmpPublishMode);
}

int wwRtmpEngineInput(ww_rtmp_engine_t *engine, const void *data, size_t size)
{
    assert(engine->started && (data || ! size));
    if (engine->phase == kRtmpClosed)
        return kRtmpInputClosed;
    const int result = engine->is_server ? rtmp_server_input(engine->connection.server, data, size)
                                         : rtmp_client_input(engine->connection.client, data, size);
    if (engine->phase == kRtmpClosed)
        return kRtmpInputClosed;
    return result > 0 ? -EINVAL : result;
}

int wwRtmpEngineAccept(ww_rtmp_engine_t *engine)
{
    assert(engine->is_server && engine->phase == kRtmpPublishing);
    return rtmp_server_start(engine->connection.server, 0, NULL);
}

int wwRtmpEngineSendData(ww_rtmp_engine_t *engine, const void *data, size_t size, uint32_t timestamp)
{
    assert(engine->phase == kRtmpActive && data && size && size <= kRtmpMaxMessageSize);
    const struct rtmp_chunk_header_t header = {
        .fmt       = RTMP_CHUNK_TYPE_0,
        .cid       = RTMP_CHANNEL_DATA,
        .timestamp = timestamp,
        .length    = (uint32_t) size,
        .type      = RTMP_TYPE_FLEX_STREAM,
        .stream_id = engine->stream_id,
    };
    return rtmp_chunk_write(engine->protocol, &header, data);
}

int ww_rtmp_profile_output(struct rtmp_t *rtmp, ww_rtmp_output_e kind, const void *header, size_t header_size,
                           const void *payload, size_t payload_size)
{
    ww_rtmp_engine_t *engine = rtmp->profile;
    return engine->callbacks.send(engine->context, header, header_size, payload, payload_size, kind);
}

int ww_rtmp_profile_event(struct rtmp_t *rtmp, ww_rtmp_event_e event, uint32_t value, uint8_t detail)
{
    ww_rtmp_engine_t *engine = rtmp->profile;
    return engine->callbacks.event(engine->context, event, value, detail);
}

int ww_rtmp_profile_ready(struct rtmp_t *rtmp)
{
    ww_rtmp_engine_t *engine = rtmp->profile;
    engine->phase            = kRtmpActive;
    return ww_rtmp_profile_event(rtmp, kRtmpEventReady, engine->stream_id, 0);
}

int ww_rtmp_profile_closed(struct rtmp_t *rtmp)
{
    rtmp->profile->phase = kRtmpClosed;
    return kRtmpInputClosed; /* Stop parsing at the terminal message, even inside a coalesced read. */
}

static int sendControl(struct rtmp_t *rtmp, const uint8_t *chunk, size_t size, ww_rtmp_output_e kind)
{
    assert(size > 0);
    return ww_rtmp_profile_output(rtmp, kind, chunk, size, NULL, 0);
}

int wwRtmpEngineAdvertiseWindow(ww_rtmp_engine_t *engine, uint32_t window)
{
    assert(engine->started && window);
    if (engine->advertised_window == window)
        return 0;
    uint8_t          chunk[32];
    int              size   = rtmp_window_acknowledgement_size(chunk, sizeof(chunk), window);
    ww_rtmp_output_e kind   = engine->phase == kRtmpActive ? kRtmpOutputUrgent : kRtmpOutputOrdered;
    int              result = sendControl(engine->protocol, chunk, (size_t) size, kind);
    if (result == 0)
        engine->advertised_window = window;
    return result;
}

int ww_rtmp_profile_advertise(struct rtmp_t *rtmp)
{
    if (rtmp->profile->advertised_window == 0)
    {
        int result = wwRtmpEngineAdvertiseWindow(rtmp->profile, kRtmpInitialAckWindow);
        if (result)
            return result;
    }
    uint8_t chunk[32];
    int     size = rtmp_set_peer_bandwidth(chunk, sizeof(chunk), kRtmpInitialPeerBandwidth, RTMP_BANDWIDTH_LIMIT_HARD);
    return sendControl(rtmp, chunk, (size_t) size, kRtmpOutputOrdered);
}

int ww_rtmp_profile_set_chunk_size(struct rtmp_t *rtmp)
{
    uint8_t chunk[32];
    int     size   = rtmp_set_chunk_size(chunk, sizeof(chunk), kRtmpOutChunkSize);
    int     result = sendControl(rtmp, chunk, (size_t) size, kRtmpOutputOrdered);
    if (result == 0)
        rtmp->out_chunk_size = kRtmpOutChunkSize;
    return result;
}

int ww_rtmp_profile_input(struct rtmp_t *rtmp, const void *input, size_t size)
{
    ww_rtmp_engine_t *engine = rtmp->profile;
    if (size > UINT64_MAX - engine->received_bytes)
        return -EINVAL;
    engine->received_bytes += size;
    if (engine->callbacks.received)
    {
        int result = engine->callbacks.received(engine->context, size);
        if (result)
            return result;
    }
    int result = rtmp_chunk_read(rtmp, input, size);
    if (result || ! engine->receive_interval)
        return result;

    uint32_t threshold = engine->receive_interval / 2;
    if (threshold > 16384)
        threshold = 16384;
    if (! threshold)
        threshold = 1;
    if (engine->received_bytes - engine->acknowledged_bytes < threshold)
        return 0;

    uint8_t chunk[32];
    int     count = rtmp_acknowledgement(chunk, sizeof(chunk), (uint32_t) engine->received_bytes);
    result        = sendControl(rtmp, chunk, (size_t) count, kRtmpOutputUrgent);
    if (result == 0)
        engine->acknowledged_bytes = engine->received_bytes;
    return result;
}

bool ww_rtmp_profile_admit(const struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header)
{
    const ww_rtmp_engine_t *engine = rtmp->profile;
    if (header->length > kRtmpMaxMessageSize)
        return false;

    /* At most three reassembly allocations are reachable, one per admitted CSID. */
    switch (header->type)
    {
    case RTMP_TYPE_INVOKE:
        return header->cid == RTMP_CHANNEL_INVOKE && header->length > 0;
    case RTMP_TYPE_FLEX_STREAM:
        return engine->phase == kRtmpActive && header->cid == RTMP_CHANNEL_DATA &&
               header->stream_id == engine->stream_id && header->length > 0;
    case RTMP_TYPE_EVENT:
    case RTMP_TYPE_SET_CHUNK_SIZE:
    case RTMP_TYPE_ABORT:
    case RTMP_TYPE_ACKNOWLEDGEMENT:
    case RTMP_TYPE_WINDOW_ACKNOWLEDGEMENT_SIZE:
    case RTMP_TYPE_SET_PEER_BANDWIDTH:
        return header->cid == RTMP_CHANNEL_PROTOCOL && header->stream_id == 0 && header->length >= 4 &&
               header->length <= 10;
    default:
        return false;
    }
}

static int abortPartialMessage(struct rtmp_t *rtmp, uint32_t chunk_stream_id)
{
    if (chunk_stream_id < 2 || chunk_stream_id > RTMP_CHANNEL_MAX)
        return -EINVAL;
    for (size_t index = 0; index < N_CHUNK_STREAM; index++)
    {
        struct rtmp_packet_t *packet = &rtmp->in_packets[index];
        if (packet->header.cid == chunk_stream_id && packet->bytes)
        {
            const bool lost_application_bytes = packet->header.type == RTMP_TYPE_FLEX_STREAM;
            memoryFree(packet->payload);
            packet->payload  = NULL;
            packet->capacity = 0;
            packet->bytes    = 0;
            return lost_application_bytes ? -ECANCELED : 0;
        }
    }
    return 0;
}

int ww_rtmp_profile_control(struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header, const uint8_t *data)
{
    uint32_t value;
    if (header->length != (header->type == RTMP_TYPE_SET_PEER_BANDWIDTH ? 5U : 4U))
        return -EINVAL;
    be_read_uint32(data, &value);
    switch (header->type)
    {
    case RTMP_TYPE_SET_CHUNK_SIZE:
        if (! value || value > kRtmpMaxInChunkSize)
            return -EINVAL;
        rtmp->in_chunk_size = value;
        return 0;
    case RTMP_TYPE_ABORT:
        return abortPartialMessage(rtmp, value);
    case RTMP_TYPE_ACKNOWLEDGEMENT:
        return ww_rtmp_profile_event(rtmp, kRtmpEventAck, value, 0);
    case RTMP_TYPE_WINDOW_ACKNOWLEDGEMENT_SIZE:
        if (! value)
            return -EINVAL;
        rtmp->profile->receive_interval = value;
        return 0;
    case RTMP_TYPE_SET_PEER_BANDWIDTH:
        if (data[4] > RTMP_BANDWIDTH_LIMIT_DYNAMIC)
            return -EINVAL;
        return ww_rtmp_profile_event(rtmp, kRtmpEventBandwidth, value, data[4]);
    default:
        return -EINVAL;
    }
}

int ww_rtmp_profile_user_control(struct rtmp_t *rtmp, const struct rtmp_chunk_header_t *header, const uint8_t *data)
{
    ww_rtmp_engine_t *engine = rtmp->profile;
    if (header->length != 6)
        return -EINVAL;
    uint16_t code;
    uint32_t value;
    be_read_uint16(data, &code);
    be_read_uint32(data + 2, &value);
    switch (code)
    {
    case RTMP_EVENT_STREAM_BEGIN:
        if (engine->is_server || engine->phase != kRtmpAwaitPublish || value != engine->stream_id)
            return -EINVAL;
        engine->stream_begin = true;
        return 0;
    case RTMP_EVENT_STREAM_EOF:
        if (engine->stream_id && value == engine->stream_id)
            return ww_rtmp_profile_closed(rtmp);
        return -EINVAL;
    case RTMP_EVENT_PING: {
        uint8_t chunk[32];
        int     size = rtmp_event_pong(chunk, sizeof(chunk), value);
        return sendControl(rtmp, chunk, (size_t) size, kRtmpOutputUrgent);
    }
    case RTMP_EVENT_PONG:
        return 0;
    default:
        return -EINVAL;
    }
}

bool ww_rtmp_profile_uint32(double value)
{
    return value >= 0 && value <= UINT32_MAX && value == (double) (uint32_t) value;
}
