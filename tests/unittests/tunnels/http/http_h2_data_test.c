/*
 * Covers: HttpCommon DATA-provider FIFO, read caps, frame completion and buffer ownership.
 * Setup: Real worker-zero buffer pool and in-memory nghttp2 client/server sessions; no tunnel lines.
 * Checks: Exact bytes, EOF storage retained until frame-send, empty/terminal providers, DATA_EXIST retry,
 *         stream/connection window stalls and resumption, failed submission and session-first cleanup.
 * Limits: Caller HEADERS admission and reentrant wire-output closure belong to the HTTP node fixtures.
 * CTest: waterwall.http_h2_data_unit (linux-unit-debug and linux-unit-release).
 */
#include "HttpCommon/h2_data.h"

#include "fixtures/worker_lines.h"

enum
{
    kWindow       = 1 << 20,
    kMaxProviders = 8,
    kPumpLimit    = 128,
};

typedef struct fixture_s
{
    twf_worker_env_t env;
    h2_data_queue_t  queue;
    nghttp2_session *sender, *peer;
    int32_t          stream_id;
    size_t           received, expected_bytes, max_frame;
    unsigned         data_frames, end_streams, retired, appended, storage_checks;
    uint32_t         expected_live;
    bool             has_buffer[kMaxProviders];
} fixture_t;

static uint8_t pattern(size_t offset)
{
    return (uint8_t) ((offset * 131U + 17U) % 251U);
}

static int receiveData(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t length,
                       void *user)
{
    discard    session;
    discard    flags;
    fixture_t *f = user;
    twfRequire(stream_id == f->stream_id, "DATA used another stream");
    twfRequire(length <= f->expected_bytes - f->received, "DATA exceeded queued bytes");
    for (size_t i = 0; i < length; ++i)
        twfRequire(data[i] == pattern(f->received + i), "DATA contents or FIFO order changed");
    f->received += length;
    return 0;
}

static int receiveFrame(nghttp2_session *session, const nghttp2_frame *frame, void *user)
{
    discard    session;
    fixture_t *f = user;
    twfRequire(frame->hd.type != NGHTTP2_GOAWAY && frame->hd.type != NGHTTP2_RST_STREAM,
               "peer rejected the test stream");
    if (frame->hd.type == NGHTTP2_DATA)
    {
        ++f->data_frames;
        f->max_frame = max(f->max_frame, frame->hd.length);
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
            ++f->end_streams;
    }
    return 0;
}

static int frameSent(nghttp2_session *session, const nghttp2_frame *frame, void *user)
{
    fixture_t *f = user;
    if (frame->hd.type == NGHTTP2_DATA && f->queue.active != NULL)
    {
        /* This is after the provider read, including its final EOF read, but before retirement. */
        twfRequireEqualU32(
            g_twf_buffers.live_count, f->expected_live, "provider read released storage before frame-send completion");
        h2_data_item_t *active    = f->queue.active;
        nghttp2_frame   unrelated = *frame;
        unrelated.hd.type         = NGHTTP2_PING;
        twfRequire(! h2DataOnFrameSent(&f->queue, &unrelated, f->stream_id), "unrelated frame type retired a provider");
        unrelated = *frame;
        unrelated.hd.stream_id += 2;
        twfRequire(! h2DataOnFrameSent(&f->queue, &unrelated, f->stream_id), "another stream retired a provider");
        twfRequire(f->queue.active == active, "unrelated callback changed active provider identity");
        ++f->storage_checks;
    }
    if (h2DataOnFrameSent(&f->queue, frame, f->stream_id))
    {
        twfRequire(f->retired < f->appended, "provider retired twice");
        if (f->has_buffer[f->retired])
            --f->expected_live;
        ++f->retired;
        twfRequireEqualU32(
            g_twf_buffers.live_count, f->expected_live, "frame completion did not recycle exactly its payload");
        h2_data_result_t result = h2DataTrySubmit(&f->queue, session, f->stream_id);
        twfRequire(result.status == H2_DATA_STARTED || result.status == H2_DATA_IDLE,
                   "next provider failed to submit at frame completion");
    }
    return 0;
}

static unsigned drain(nghttp2_session *from, nghttp2_session *to)
{
    for (unsigned i = 0; i < kPumpLimit; ++i)
    {
        const uint8_t *wire   = NULL;
        nghttp2_ssize  length = nghttp2_session_mem_send2(from, &wire);
        twfRequire(length >= 0, "nghttp2 serialization failed");
        if (length == 0)
            return i;
        twfRequire(nghttp2_session_mem_recv2(to, wire, (size_t) length) == length,
                   "peer did not consume serialized output");
    }
    twfRequire(false, "nghttp2 output did not become idle within the bounded pump");
    return 0;
}

static unsigned exchange(fixture_t *f)
{
    unsigned total = 0;
    for (unsigned i = 0; i < kPumpLimit; ++i)
    {
        unsigned sent = drain(f->sender, f->peer);
        sent += drain(f->peer, f->sender);
        total += sent;
        if (sent == 0)
            return total;
    }
    twfRequire(false, "nghttp2 peers did not settle within the bounded exchange");
    return 0;
}

static void setup(fixture_t *f, uint32_t max_read, uint32_t stream_window, uint32_t connection_window)
{
    memoryZero(f, sizeof(*f));
    twfWorkerEnvSetup(&f->env, 131072, 0);
    h2DataInit(&f->queue, f->env.pool, max_read);
    nghttp2_session_callbacks *callbacks = NULL;
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "callback allocation failed");
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, frameSent);
    twfRequire(nghttp2_session_client_new(&f->sender, callbacks, f) == 0, "sender creation failed");
    nghttp2_session_callbacks_del(callbacks);
    twfRequire(nghttp2_session_callbacks_new(&callbacks) == 0, "peer callback allocation failed");
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, receiveData);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, receiveFrame);
    nghttp2_option *options = NULL;
    twfRequire(nghttp2_option_new(&options) == 0, "peer option allocation failed");
    nghttp2_option_set_no_auto_window_update(options, 1);
    twfRequire(nghttp2_session_server_new2(&f->peer, callbacks, f, options) == 0, "peer creation failed");
    nghttp2_option_del(options);
    nghttp2_session_callbacks_del(callbacks);
    const nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, stream_window},
                                               {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 65536}};
    twfRequire(nghttp2_submit_settings(f->sender, NGHTTP2_FLAG_NONE, NULL, 0) == 0,
               "sender settings submission failed");
    twfRequire(nghttp2_submit_settings(f->peer, NGHTTP2_FLAG_NONE, settings, ARRAY_SIZE(settings)) == 0,
               "peer settings submission failed");
    if (connection_window > 65535)
        twfRequire(nghttp2_submit_window_update(f->peer, NGHTTP2_FLAG_NONE, 0, (int32_t) (connection_window - 65535)) ==
                       0,
                   "peer connection window submission failed");
    exchange(f);
    nghttp2_nv headers[] = {
        {(uint8_t *) ":method", (uint8_t *) "POST", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":scheme", (uint8_t *) "http", 7, 4, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":path", (uint8_t *) "/data", 5, 5, NGHTTP2_NV_FLAG_NONE},
        {(uint8_t *) ":authority", (uint8_t *) "unit.test", 10, 9, NGHTTP2_NV_FLAG_NONE},
    };
    f->stream_id =
        nghttp2_submit_headers(f->sender, NGHTTP2_FLAG_END_HEADERS, -1, NULL, headers, ARRAY_SIZE(headers), NULL);
    twfRequire(f->stream_id == 1, "request stream creation failed");
    exchange(f);
}

static void append(fixture_t *f, uint32_t length, bool allocated, bool end_stream)
{
    twfRequire(f->appended < kMaxProviders, "too many fixture providers");
    sbuf_t *payload = NULL;
    if (allocated)
    {
        payload = bufferpoolGetBestFit(f->env.pool, length, 0);
        sbufSetLength(payload, length);
        for (uint32_t i = 0; i < length; ++i)
            sbufGetMutablePtr(payload)[i] = pattern(f->expected_bytes + i);
        ++f->expected_live;
    }
    f->has_buffer[f->appended++] = allocated;
    f->expected_bytes += length;
    h2DataAppend(&f->queue, payload, end_stream);
}

static void start(fixture_t *f)
{
    h2_data_result_t result = h2DataTrySubmit(&f->queue, f->sender, f->stream_id);
    twfRequire(result.status == H2_DATA_STARTED && result.nghttp2_error == 0, "queued provider did not start");
}

static void teardown(fixture_t *f)
{
    if (f->sender != NULL)
        nghttp2_session_del(f->sender);
    f->sender = NULL;
    h2DataDestroyAfterSession(&f->queue);
    twfRequire(f->queue.head == NULL && f->queue.tail == NULL && f->queue.active == NULL,
               "queue retained provider storage after destruction");
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(twfRecycleCount(), g_twf_buffers.total_acquired, "payloads were not recycled exactly once");
    nghttp2_session_del(f->peer);
    twfWorkerEnvTeardown(&f->env);
}

static void caseFifoAndReadCap(uint32_t max_read)
{
    twfSetCase(max_read == UINT32_MAX ? "H2 server DATA reads retain the nghttp2 cap"
                                      : "H2 client DATA reads retain the 16375-byte cap");
    fixture_t f;
    setup(&f, max_read, kWindow, kWindow);
    twfRequire(h2DataTrySubmit(&f.queue, f.sender, f.stream_id).status == H2_DATA_IDLE, "empty queue was not idle");
    append(&f, 65536, true, false);
    append(&f, 731, true, false);
    append(&f, 0, false, true);
    start(&f);
    exchange(&f);
    twfRequire(f.received == 65536 + 731 && f.end_streams == 1 && f.retired == 3,
               "FIFO data or terminal completion was lost");
    twfRequire(f.max_frame == (max_read == UINT32_MAX ? 16384U : 16375U), "provider read cap changed");
    twfRequire(f.data_frames == (max_read == UINT32_MAX ? 6U : 7U), "DATA fragmentation changed");
    twfRequire(f.storage_checks == f.data_frames, "frame-completion storage boundary was not checked");
    twfRequire(f.queue.head == NULL && f.queue.active == NULL, "completed FIFO retained providers");
    teardown(&f);
}

static void caseEmptyProvider(bool allocated, bool terminal)
{
    twfSetCase(terminal ? "H2 empty terminal provider sends one END_STREAM"
                        : "H2 empty nonterminal provider preserves teardown settlement");
    fixture_t f;
    setup(&f, 16375, kWindow, kWindow);
    append(&f, 0, allocated, terminal);
    if (! terminal)
        append(&f, 4, true, false);
    start(&f);
    h2_data_item_t *active = f.queue.active;
    exchange(&f);
    if (terminal)
    {
        twfRequire(f.data_frames == 1 && f.end_streams == 1 && f.retired == 1 && f.received == 0,
                   "empty terminal provider did not finish exactly once");
    }
    else
    {
        /* nghttp2 suppresses empty EOF|NO_END_STREAM DATA and its frame-send callback.
         * Preserve the existing provider lifetime; HTTP callers filter non-null empty input. */
        twfRequire(f.data_frames == 0 && f.end_streams == 0 && f.retired == 0,
                   "empty nonterminal provider changed wire behavior");
        twfRequire(f.queue.active == active && f.queue.head != NULL,
                   "suppressed provider or pending input lost ownership");
        twfRequire(h2DataTrySubmit(&f.queue, f.sender, f.stream_id).status == H2_DATA_IDLE,
                   "suppressed active provider allowed another submission");
    }
    teardown(&f);
}

static ssize_t foreignRead(nghttp2_session *session, int32_t stream_id, uint8_t *data, size_t length, uint32_t *flags,
                           nghttp2_data_source *source, void *user)
{
    discard session;
    discard stream_id;
    discard source;
    discard user;
    twfRequire(length > 0, "foreign provider received no capacity");
    data[0] = pattern(0);
    *flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
    return 1;
}

static void caseDataExists(void)
{
    twfSetCase("H2 DATA_EXIST retains the same front and FIFO for retry");
    fixture_t f;
    setup(&f, 16375, kWindow, kWindow);
    const nghttp2_data_provider provider = {.read_callback = foreignRead};
    twfRequire(nghttp2_submit_data(f.sender, NGHTTP2_FLAG_NONE, f.stream_id, &provider) == 0,
               "foreign provider submission failed");
    f.expected_bytes = 1;
    append(&f, 19, true, false);
    h2_data_item_t *head = f.queue.head;
    append(&f, 23, true, false);
    h2_data_item_t  *tail   = f.queue.tail;
    h2_data_result_t result = h2DataTrySubmit(&f.queue, f.sender, f.stream_id);
    twfRequire(result.status == H2_DATA_BLOCKED && result.nghttp2_error == NGHTTP2_ERR_DATA_EXIST,
               "occupied nghttp2 stream did not report BLOCKED");
    twfRequire(f.queue.head == head && f.queue.tail == tail && f.queue.active == NULL,
               "DATA_EXIST changed queue order or ownership");
    twfRequireEqualU32(twfRecycleCount(), 0, "DATA_EXIST released a queued payload");
    exchange(&f);
    twfRequire(f.received == 1 && f.retired == 0, "foreign completion retired an unsubmitted provider");
    start(&f);
    twfRequire(f.queue.active == head && f.queue.head == tail, "retry did not submit the original front");
    exchange(&f);
    twfRequire(f.received == 43 && f.retired == 2 && f.end_streams == 0, "retry lost or duplicated DATA");
    teardown(&f);
}

static void caseWindowExhaustion(bool connection)
{
    twfSetCase(connection ? "H2 connection window resumes the same provider"
                          : "H2 stream window resumes the same provider");
    fixture_t f;
    setup(&f, 16375, connection ? kWindow : 1024, connection ? 65535 : kWindow);
    uint32_t length = connection ? 70000 : 4096;
    append(&f, length, true, false);
    append(&f, 17, true, false);
    start(&f);
    h2_data_item_t *active  = f.queue.active;
    h2_data_item_t *pending = f.queue.head;
    exchange(&f);
    twfRequire(f.received == (connection ? 65535U : 1024U) && f.retired == 0,
               "window exhaustion did not retain the partial provider");
    twfRequire(f.queue.active == active && f.queue.head == pending, "window stall changed provider identities");
    twfRequire(h2DataTrySubmit(&f.queue, f.sender, f.stream_id).status == H2_DATA_IDLE && exchange(&f) == 0,
               "window-stalled provider reported new progress");
    twfRequire(nghttp2_submit_window_update(f.peer, NGHTTP2_FLAG_NONE, connection ? 0 : f.stream_id, kWindow) == 0,
               "window resumption submission failed");
    exchange(&f);
    twfRequire(f.received == length + 17 && f.retired == 2 && f.end_streams == 0,
               "WINDOW_UPDATE failed to resume exact queued bytes");
    teardown(&f);
}

static void caseSubmissionFailure(void)
{
    twfSetCase("H2 failed submission releases only its rejected payload");
    fixture_t f;
    setup(&f, 16375, kWindow, kWindow);
    append(&f, 16, true, false);
    append(&f, 8, true, false);
    h2_data_item_t  *pending = f.queue.tail;
    h2_data_result_t result  = h2DataTrySubmit(&f.queue, f.sender, f.stream_id + 2);
    twfRequire(result.status == H2_DATA_FAILED && result.nghttp2_error == NGHTTP2_ERR_STREAM_CLOSED,
               "missing stream did not report the nghttp2 submission failure");
    twfRequire(f.queue.active == NULL && f.queue.head == pending && f.queue.tail == pending,
               "failed submission lost remaining queue ownership");
    twfRequireEqualU32(twfRecycleCount(), 1, "failed submission did not release exactly one payload");
    twfRequireEqualU32(g_twf_buffers.live_count, 1, "failed submission released pending payload");
    teardown(&f);
}

static void caseSessionFirstCleanup(void)
{
    twfSetCase("H2 session deletion precedes partially read active and pending cleanup");
    fixture_t f;
    setup(&f, 16375, 1024, kWindow);
    append(&f, 4096, true, false);
    append(&f, 17, true, false);
    start(&f);
    exchange(&f);
    twfRequire(f.received == 1024 && f.queue.active != NULL && f.queue.head != NULL,
               "cleanup did not begin with both partial and pending providers");
    twfRequireEqualU32(twfRecycleCount(), 0, "partial provider was prematurely recycled");
    nghttp2_session_del(f.sender);
    f.sender = NULL;
    twfRequireEqualU32(g_twf_buffers.live_count, 2, "session deletion took payload ownership");
    teardown(&f);
}

int main(void)
{
    caseFifoAndReadCap(16375);
    caseFifoAndReadCap(UINT32_MAX);
    caseEmptyProvider(false, true);
    caseEmptyProvider(true, true);
    caseEmptyProvider(false, false);
    caseEmptyProvider(true, false);
    caseDataExists();
    caseWindowExhaustion(false);
    caseWindowExhaustion(true);
    caseSubmissionFailure();
    caseSessionFirstCleanup();
    return 0;
}
