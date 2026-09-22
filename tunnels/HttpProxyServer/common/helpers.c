#include "AuthenticationClient/interface.h"
#include "structure.h"

static uint64_t nowMs(void)
{
    return getHRTimeUs() / 1000;
}

static hps_tstate_t *settings(hps_session_t *s)
{
    return tunnelGetState(s->t);
}

static bool active(hps_session_t *s)
{
    return s->phase != kHpsClosed && lineIsAlive(s->client);
}

void hpsRetain(hps_session_t *s)
{
    ++s->references;
}

void hpsRelease(hps_session_t *s)
{
    if (--s->references == 0)
    {
        assert(s->phase == kHpsClosed);
        lineUnref(s->client);
        memoryZero(s->credentials, sizeof(s->credentials));
        memoryFree(s);
    }
}

static void clearSlot(line_t *l, tunnel_t *t)
{
    memoryZeroAligned32(lineGetState(l, t), tunnelGetCorrectAlignedLineStateSize(sizeof(hps_lstate_t)));
}

static void discardBuffer(hps_session_t *s, sbuf_t **slot)
{
    if (*slot)
    {
        sbuf_t *b = *slot;
        *slot     = NULL;
        lineReuseBuffer(s->client, b);
    }
}

static void clearHeader(hps_session_t *s, unsigned d)
{
    if (s->header_storage[d])
    {
        memoryZero(s->header_storage[d], s->header_length[d]);
        memoryFree(s->header_storage[d]);
        s->header_storage[d] = NULL;
    }
    s->trailer_context[d] = (hps_header_t) {0};
    s->header_length[d]   = 0;
}

void hpsDetachTimer(hps_session_t *s)
{
    if (! s->timer)
        return;
    hps_worker_t *w = &settings(s)->workers[lineGetWID(s->client)];
    if (s->timer_prev)
        s->timer_prev->timer_next = s->timer_next;
    else
        w->timers = s->timer_next;
    if (s->timer_next)
        s->timer_next->timer_prev = s->timer_prev;
    wtimer_t *timer = s->timer;
    s->timer        = NULL;
    s->timer_prev = s->timer_next = NULL;
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

void hpsCloseChild(hps_session_t *s, bool from_child)
{
    line_t *child = s->child;
    if (! child)
        return;
    hps_lstate_t *ls     = lineGetState(child, s->t);
    hps_worker_t *w      = &settings(s)->workers[lineGetWID(child)];
    s->child             = NULL;
    s->child_established = false;
    s->connect_at        = 0;
    s->paused[0]         = false;
    s->read_paused[1]    = false;
    if (ls->prev)
        ls->prev->next = ls->next;
    else
        w->children = ls->next;
    if (ls->next)
        ls->next->prev = ls->prev;
    lineRef(child);
    clearSlot(child, s->t);
    if (! from_child)
        tunnelNextUpStreamFinish(s->t, child);
    lineDestroy(child);
    lineUnref(child);
}

void hpsClose(hps_session_t *s, bool from_client)
{
    if (s->phase == kHpsClosed)
        return;
    s->phase = kHpsClosed;
    hpsDetachTimer(s);
    clearSlot(s->client, s->t);
    hpsCloseChild(s, false);
    for (unsigned i = 0; i < 2; ++i)
    {
        discardBuffer(s, &s->input[i]);
        discardBuffer(s, &s->output[i]);
        discardBuffer(s, &s->deferred[i]);
        clearHeader(s, i);
    }
    if (! from_client)
        tunnelPrevDownStreamFinish(s->t, s->client);
    hpsRelease(s); /* borrowed client slot's session reference */
}

static size_t pending(hps_session_t *s)
{
    size_t n = 0;
    for (unsigned i = 0; i < 2; ++i)
    {
        if (s->input[i])
            n += sbufGetLength(s->input[i]);
        if (s->output[i])
            n += sbufGetLength(s->output[i]);
    }
    return n;
}

static uint64_t retained(hps_session_t *s)
{
    uint64_t n = pending(s);
    for (unsigned d = 0; d < 2; ++d)
        if (s->deferred[d])
            n += sbufGetLength(s->deferred[d]);
    return n;
}

static uint64_t bufferCharge(const sbuf_t *buffer)
{
    return buffer ? (uint64_t) sbufGetTotalCapacity(buffer) + sizeof(sbuf_t) + kSbufAllocationAlignment : 0;
}

static bool remainderAllocationFits(hps_session_t *s, const sbuf_t *buffer)
{
    buffer_pool_t *pool          = lineGetBufferPool(s->client);
    const uint64_t payload_bound = max((uint64_t) bufferpoolGetSmallBufferSize(pool), 2 * kHpsDeliveryHeadroomBytes);
    const uint16_t padding       = max(bufferpoolGetMediumBufferPadding(pool),
                                 max(bufferpoolGetSmallBufferPadding(pool), bufferpoolGetLargeBufferPadding(pool)));
    uint32_t       capacity;
    return sbufTryComputeCapacity(payload_bound, padding, &capacity) &&
           bufferCharge(buffer) <= (uint64_t) capacity + sizeof(sbuf_t) + kSbufAllocationAlignment;
}

/* Four coalesced retained buffers bound entries independently of TCP fragmentation. */
static bool allocationFits(hps_session_t *s, const sbuf_t *replace, const sbuf_t *candidate)
{
    uint64_t charge = bufferCharge(candidate);
    for (unsigned i = 0; i < 2; ++i)
    {
        const sbuf_t *buffers[] = {s->input[i], s->output[i]};
        for (unsigned j = 0; j < 2; ++j)
            if (buffers[j] && buffers[j] != replace)
                charge += bufferCharge(buffers[j]);
    }
    return charge <= (uint64_t) settings(s)->max_pending * 4;
}

static sbuf_t *makeBuffer(hps_session_t *s, size_t n)
{
    buffer_pool_t *pool = lineGetBufferPool(s->client);
    sbuf_t        *b    = bufferpoolTryGetBestFit(pool, n, bufferpoolGetLargeBufferPadding(pool));
    if (b == NULL)
        return NULL;
    if (sbufGetMaximumWriteableSize(b) < n)
    {
        lineReuseBuffer(s->client, b);
        return NULL;
    }
    return b;
}

static bool appendInput(hps_session_t *s, unsigned direction, const unsigned char *data, size_t n)
{
    if (n > settings(s)->max_pending - pending(s))
        return false;
    sbuf_t *old    = s->input[direction];
    size_t  length = old ? sbufGetLength(old) : 0;
    if (! old || sbufGetMaximumWriteableSize(old) < length + n)
    {
        sbuf_t *b = makeBuffer(s, MIN_SIZE(settings(s)->max_pending, MAX_SIZE(4096, (length + n) * 2)));
        if (! b)
            return false;
        if (! allocationFits(s, old, b))
        {
            lineReuseBuffer(s->client, b);
            return false;
        }
        if (length)
            memoryCopy(sbufGetMutablePtr(b), sbufGetRawPtr(old), length);
        discardBuffer(s, &s->input[direction]);
        s->input[direction] = old = b;
    }
    memoryCopy(sbufGetMutablePtr(old) + length, data, n);
    sbufSetLength(old, (uint32_t) (length + n));
    return true;
}

static void consume(hps_session_t *s, unsigned d, size_t n)
{
    sbuf_t *b = s->input[d];
    if (n == sbufGetLength(b))
        discardBuffer(s, &s->input[d]);
    else
        sbufShiftRight(b, (uint32_t) n);
}

static bool output(hps_session_t *s, unsigned d, const char *data, size_t n)
{
    assert(! s->output[d]);
    if (n > settings(s)->max_pending - pending(s))
        return false;
    sbuf_t *b = makeBuffer(s, n);
    if (! b)
        return false;
    if (! allocationFits(s, NULL, b))
    {
        lineReuseBuffer(s->client, b);
        return false;
    }
    memoryCopy(sbufGetMutablePtr(b), data, n);
    sbufSetLength(b, (uint32_t) n);
    s->output[d] = b;
    return true;
}

static void fail(hps_session_t *s, unsigned status)
{
    if (! active(s))
        return;
    if (s->final_committed || s->phase == kHpsRelay || s->phase == kHpsError)
    {
        hpsClose(s, false);
        return;
    }
    s->phase = kHpsError;
    hpsCloseChild(s, false);
    for (unsigned i = 0; i < 2; ++i)
    {
        discardBuffer(s, &s->input[i]);
        discardBuffer(s, &s->output[i]);
        discardBuffer(s, &s->deferred[i]);
    }
    const char *reason = "Bad Request";
    switch (status)
    {
    case 405:
        reason = "Method Not Allowed";
        break;
    case 407:
        reason = "Proxy Authentication Required";
        break;
    case 408:
        reason = "Request Timeout";
        break;
    case 414:
        reason = "URI Too Long";
        break;
    case 417:
        reason = "Expectation Failed";
        break;
    case 431:
        reason = "Request Header Fields Too Large";
        break;
    case 501:
        reason = "Not Implemented";
        break;
    case 502:
        reason = "Bad Gateway";
        break;
    case 503:
        reason = "Service Unavailable";
        break;
    case 504:
        reason = "Gateway Timeout";
        break;
    case 505:
        reason = "HTTP Version Not Supported";
        break;
    }
    char text[384];
    int  n = stringNPrintf(text,
                          sizeof(text),
                          "HTTP/1.%c %u %s\r\nContent-Length: 0\r\nConnection: close\r\n%s\r\n",
                          s->http10 ? '0' : '1',
                          status,
                          reason,
                          status == 407   ? "Proxy-Authenticate: Basic realm=\"WaterWall\"\r\n"
                           : status == 405 ? "Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS, CONNECT\r\n"
                                           : "");
    if (! output(s, 1, text, (size_t) n))
        hpsClose(s, false);
}

static void pressure(hps_session_t *s)
{
    if (! active(s) || settings(s)->workers[lineGetWID(s->client)].quiescing)
        return;
    for (unsigned d = 0; d < 2 && active(s); ++d)
    {
        /* Future requests cannot drain until the current response arrives. Reserve
         * headroom by stopping client input, without stopping that response producer.
         * Recompute after each callback: a Resume can synchronously drain buffers. */
        uint64_t n    = d == 0 ? retained(s)
                               : (uint64_t) (s->input[1] ? sbufGetLength(s->input[1]) : 0) +
                                  (s->output[1] ? sbufGetLength(s->output[1]) : 0) +
                                  (s->deferred[1] ? sbufGetLength(s->deferred[1]) : 0);
        bool     want = s->paused[d] || s->deferred[d] != NULL || n >= settings(s)->max_pending * 3 / 4 ||
                    (d == 0 && (s->upload_stopped || s->phase == kHpsError));
        if (! want && n > settings(s)->max_pending / 2 && s->read_paused[d])
            want = true;
        if (want == s->read_paused[d] || (d == 1 && ! s->child_established))
            continue;
        s->read_paused[d] = want;
        line_t *line      = d == 0 ? s->client : s->child;
        lineRef(line);
        if (d == 0)
        {
            if (want)
                tunnelPrevDownStreamPause(s->t, line);
            else
                tunnelPrevDownStreamResume(s->t, line);
        }
        else
        {
            if (want)
                tunnelNextUpStreamPause(s->t, line);
            else
                tunnelNextUpStreamResume(s->t, line);
        }
        lineUnref(line);
        s->again = true;
    }
}

static bool deliver(hps_session_t *s, unsigned d, sbuf_t *b)
{
    line_t *line = d == 0 ? s->child : s->client;
    lineRef(line);
    s->progress_at = nowMs();
    if (d == 0)
        tunnelNextUpStreamPayload(s->t, line, b);
    else
        tunnelPrevDownStreamPayload(s->t, line, b);
    bool alive = lineIsAlive(line);
    lineUnref(line);
    return alive && active(s);
}

static bool flush(hps_session_t *s, unsigned d)
{
    if (! s->output[d] || s->paused[d] || (d == 0 && ! s->child_established))
        return false;
    sbuf_t *b    = s->output[d];
    s->output[d] = NULL;
    if (d == 1 && (s->phase == kHpsError || s->phase == kHpsRelay || ! s->response_header))
        s->final_committed = true;
    deliver(s, d, b);
    return true;
}

/* The complete block alone is copied; body and pipelined tails remain in their input stream. */
static int header(hps_session_t *s, unsigned d, char **block)
{
    sbuf_t *b = s->input[d];
    if (! b)
        return 0;
    if (! s->header_at[d])
        s->header_at[d] = nowMs();
    size_t               len = sbufGetLength(b), n = 0;
    const unsigned char *p = sbufGetRawPtr(b);
    for (size_t i = 0; i + 3 < len; ++i)
        if (! memoryCompare(p + i, "\r\n\r\n", 4))
        {
            n = i + 4;
            break;
        }
    if ((! n && len >= settings(s)->max_header) || n > settings(s)->max_header)
        return -431;
    size_t line = 0;
    while (line < len && p[line] != '\r' && p[line] != '\n')
        ++line;
    if (line > kHpsRequestLineLimit)
        return -414;
    if (! n)
        return 0;
    *block = memoryAllocate(n + 1);
    if (! *block)
        return -503;
    memoryCopy(*block, p, n);
    (*block)[n] = 0;
    consume(s, d, n);
    s->header_at[d] = 0;
    return (int) n;
}

static bool rewrite(hps_session_t *s, const hps_header_t *h, unsigned d)
{
    size_t cap  = (size_t) settings(s)->max_header + 1024;
    char  *text = memoryAllocate(cap);
    if (! text)
        return false;
    size_t n = 0;
    bool ok  = hpsRewriteHeader(h, d == 1, s->http10, d == 1 && s->close_after, text, cap, &n) && output(s, d, text, n);
    memoryFree(text);
    return ok;
}

static void createChild(hps_session_t *s, const char *username, const char *password)
{
    line_t       *l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(s->t)), lineGetWID(s->client));
    hps_lstate_t *ls = lineGetState(l, s->t);
    *ls              = (hps_lstate_t) {.session = s, .line = l, .child = true};
    hps_worker_t *w  = &settings(s)->workers[lineGetWID(l)];
    ls->next         = w->children;
    if (ls->next)
        ls->next->prev = ls;
    w->children   = ls;
    s->child      = l;
    s->child_eof  = false;
    s->connect_at = nowMs();
    addresscontextCopy(lineGetSourceAddressContext(l), lineGetSourceAddressContext(s->client));
    lineGetRoutingContext(l)->local_listener_port = lineGetRoutingContext(s->client)->local_listener_port;
    lineGetRoutingContext(l)->peer_source_port    = lineGetRoutingContext(s->client)->peer_source_port;
    lineCopyUsers(l, s->client);
    if (s->auth_mode == kHpsAuthLocal)
        lineAddAuthenticatedCredentials(l, username, password);
    else if (s->auth_mode == kHpsAuthTracked)
    {
        lineAddUser(l, &s->identity, username, password);
    }
    address_context_t *dest = lineGetDestinationAddressContext(l);
    if (s->authority.literal)
        addresscontextSetIp(dest, &s->authority.ip);
    else
        addresscontextDomainSetByString(dest, s->authority.host);
    addresscontextSetPort(dest, s->authority.port);
    addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    lineRef(l);
    tunnelNextUpStreamInit(s->t, l);
    lineUnref(l);
}

static bool request(hps_session_t *s)
{
    char *block = NULL;
    int   n     = header(s, 0, &block);
    if (! n)
        return false;
    if (n < 0)
    {
        fail(s, (unsigned) -n);
        return true;
    }
    hps_header_t h;
    unsigned     error          = hpsParseHeader(block, (size_t) n, false, false, &h);
    s->http10                   = h.http10;
    char          username[256] = {0}, password[256] = {0}, key[512] = {0};
    user_handle_t identity = {0};
    hps_tstate_t *ts       = settings(s);
    if (! error && ts->auth_mode != kHpsAuthNone)
    {
        if (! hpsDecodeBasic(h.credentials, username, password, key))
            error = 407;
        else if (ts->auth_mode == kHpsAuthLocal)
        {
            bool matched = false;
            for (size_t i = 0; i < ts->user_count; ++i)
                if (! stringCompare(username, ts->users[i].username) &&
                    ! stringCompare(password, ts->users[i].password))
                {
                    matched = true;
                    break;
                }
            if (! matched)
                error = 407;
        }
        else if (! authenticationclientIsReady(ts->auth))
            error = 503;
        else
        {
            authenticationclient_user_lookup_result_t result =
                authenticationclientGetUserByPasswordWithResult(settings(s)->auth, key, &identity);
            if (result != kAuthenticationClientUserLookupOk)
                error = result == kAuthenticationClientUserLookupUsersUnavailable ? 503 : 407;
        }
        if (! error && lineGetUserAuthCount(s->client) >= kLineMaxUsers)
            error = 503;
    }
    if (! error)
    {
        bool reuse = s->child && ! h.connect && s->auth_mode == ts->auth_mode &&
                     hpsAuthorityEqual(&s->authority, &h.authority) && identity.generation == s->identity.generation &&
                     identity.user_id == s->identity.user_id && ! stringCompare(key, s->credentials);
        if (! reuse)
            hpsCloseChild(s, false);
        s->http10          = h.http10;
        s->head            = h.head;
        s->close_after     = h.close;
        s->child_reusable  = true;
        s->upload_stopped  = false;
        s->final_committed = false;
        s->informationals  = 0;
        s->response_header = true;
        s->request_body    = h.body;
        s->response_body   = (hps_body_t) {0};
        clearHeader(s, 0);
        clearHeader(s, 1);
        s->authority = h.authority;
        s->identity  = identity;
        s->auth_mode = ts->auth_mode;
        memoryCopy(s->credentials, key, sizeof(key));
        if (h.local_options)
        {
            s->phase     = kHpsError; /* local response then close, without draining an optional body */
            char reply[] = "HTTP/1.1 200 OK\r\nAllow: GET, HEAD, POST, PUT, DELETE, OPTIONS, CONNECT\r\n"
                           "Content-Length: 0\r\nConnection: close\r\n\r\n";
            reply[7]     = s->http10 ? '0' : '1';
            if (! output(s, 1, reply, stringLength(reply)))
                error = 503;
        }
        else
        {
            s->phase = h.connect ? kHpsConnect : kHpsExchange;
            if (! h.connect && ! rewrite(s, &h, 0))
                error = 503;
            if (! error && h.chunked)
            {
                s->trailer_context[0] = h;
                s->header_storage[0]  = block;
                s->header_length[0]   = (size_t) n;
                block                 = NULL;
            }
            if (! error && ! reuse)
                createChild(s, username, password);
        }
    }
    memoryZero(password, sizeof(password));
    memoryZero(key, sizeof(key));
    if (block)
    {
        memoryZero(block, (size_t) n);
        memoryFree(block);
    }
    if (error)
        fail(s, error);
    return true;
}

static bool response(hps_session_t *s)
{
    char *block = NULL;
    int   n     = header(s, 1, &block);
    if (! n)
        return false;
    if (n < 0)
    {
        fail(s, 502);
        return true;
    }
    hps_header_t h;
    unsigned     error = hpsParseHeader(block, (size_t) n, true, s->head, &h);
    if (! error && h.status < 200 && ++s->informationals > kHpsInformationalLimit)
        error = 502;
    if (! error)
    {
        if (h.status >= 200)
        {
            s->response_header = false;
            s->response_body   = h.body;
            s->child_reusable  = ! h.close && h.body.kind != kHpsBodyEof;
            s->close_after |= h.close || h.body.kind == kHpsBodyEof;
            if (s->request_body.kind != kHpsBodyDone)
            {
                s->upload_stopped = true;
                s->close_after    = true;
                s->child_reusable = false;
                discardBuffer(s, &s->input[0]);
                discardBuffer(s, &s->output[0]);
                discardBuffer(s, &s->deferred[0]);
            }
        }
        if (! (s->http10 && h.status < 200) && ! rewrite(s, &h, 1))
            error = 503;
        if (! error && h.chunked && h.status >= 200)
        {
            clearHeader(s, 1);
            s->trailer_context[1] = h;
            s->header_storage[1]  = block;
            s->header_length[1]   = (size_t) n;
            block                 = NULL;
        }
    }
    memoryFree(block);
    if (error)
        fail(s, 502);
    return true;
}

typedef enum hps_step_e
{
    kHpsStepBlocked,
    kHpsStepNeedInput,
    kHpsStepProgress,
    kHpsStepDone
} hps_step_t;

static hps_step_t body(hps_session_t *s, unsigned d)
{
    hps_body_t *b = d == 0 ? &s->request_body : &s->response_body;
    if (b->kind == kHpsBodyDone)
        return kHpsStepDone;
    if (s->paused[d] || s->output[d])
        return kHpsStepBlocked;
    if (! s->input[d])
        return kHpsStepNeedInput;
    size_t used;
    bool   emit;
    int    result = hpsBodyStep(b,
                             sbufGetRawPtr(s->input[d]),
                             sbufGetLength(s->input[d]),
                             d == 1 && s->http10,
                             &s->trailer_context[d],
                             &used,
                             &emit);
    if (result < 0)
    {
        fail(s, d == 0 ? 400 : 502);
        return kHpsStepProgress;
    }
    if (! result)
        return kHpsStepNeedInput;
    if (b->kind == kHpsBodyDone)
        clearHeader(s, d);
    sbuf_t *out = NULL;
    if (emit)
    {
        out = makeBuffer(s, used);
        if (! out)
        {
            fail(s, 503);
            return kHpsStepProgress;
        }
        memoryCopy(sbufGetMutablePtr(out), sbufGetRawPtr(s->input[d]), used);
        sbufSetLength(out, (uint32_t) used);
    }
    consume(s, d, used);
    s->progress_at = nowMs();
    if (out)
        deliver(s, d, out);
    return kHpsStepProgress;
}

static bool admitDeferred(hps_session_t *s, unsigned d)
{
    if (! s->deferred[d] || s->paused[d] || s->phase == kHpsError)
        return false;
    if (d == 0 && (s->upload_stopped || s->phase == kHpsConnect ||
                   (s->phase == kHpsExchange && (! s->child_established || s->request_body.kind == kHpsBodyDone))))
        return false;
    size_t room = settings(s)->max_pending - pending(s);
    if ((d == 0 ? s->phase == kHpsRequest : s->response_header) && room > 1024)
        room -= 1024;
    size_t n = min(min((size_t) 16384, sbufGetLength(s->deferred[d])), room);
    if (! n)
        return false;
    if (! appendInput(s, d, sbufGetRawPtr(s->deferred[d]), n))
    {
        fail(s, 503);
        return true;
    }
    if (n == sbufGetLength(s->deferred[d]))
        discardBuffer(s, &s->deferred[d]);
    else
        sbufShiftRight(s->deferred[d], (uint32_t) n);
    s->progress_at = nowMs();
    return true;
}

static void pump(hps_session_t *s)
{
    if (s->pumping)
    {
        s->again = true;
        return;
    }
    s->pumping = true;
    do
    {
        s->again = false;
        if (! active(s) || settings(s)->workers[lineGetWID(s->client)].quiescing)
            break;
        if (admitDeferred(s, 1))
            s->again = true;
        if (active(s) && admitDeferred(s, 0))
            s->again = true;
        if (! active(s))
            break;
        if (flush(s, 1))
            s->again = true;
        if (! active(s))
            break;
        if (s->phase == kHpsError)
        {
            if (! s->output[1])
                hpsClose(s, false);
            break;
        }
        if (s->phase == kHpsRequest)
        {
            if (s->input[1])
            {
                fail(s, 502);
                s->again = true;
                continue;
            }
            if (request(s))
                s->again = true;
        }
        if (! active(s))
            break;
        if (s->phase == kHpsConnect && s->child_established)
        {
            char success[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            success[7]     = s->http10 ? '0' : '1';
            s->phase       = kHpsRelay;
            if (! output(s, 1, success, stringLength(success)))
                fail(s, 503);
            s->again = true;
        }
        if (! active(s))
            break;
        if (s->phase == kHpsRelay && ! s->output[1])
        {
            for (unsigned d = 0; d < 2 && active(s); ++d)
                if (s->input[d] && ! s->paused[d])
                {
                    sbuf_t *b   = s->input[d];
                    s->input[d] = NULL;
                    deliver(s, d, b);
                    s->again = true;
                }
        }
        if (! active(s))
            break;
        if (s->phase == kHpsExchange)
        {
            bool needs_input = false;
            if (s->response_header && ! s->output[1])
            {
                if (response(s))
                    s->again = true;
                else
                    needs_input = true;
            }
            if (! active(s) || s->phase != kHpsExchange)
                continue;
            if (flush(s, 0))
                s->again = true;
            if (! active(s) || s->phase != kHpsExchange)
                continue;
            if (s->child_established && ! s->upload_stopped && body(s, 0) == kHpsStepProgress)
                s->again = true;
            if (! active(s) || s->phase != kHpsExchange)
                continue;
            if (! s->response_header)
            {
                hps_step_t step = body(s, 1);
                if (step == kHpsStepProgress)
                    s->again = true;
                needs_input = step == kHpsStepNeedInput;
            }
            if (! active(s) || s->phase != kHpsExchange)
                continue;
            if (s->child_eof && s->response_body.kind == kHpsBodyEof && ! s->input[1] && ! s->deferred[1])
                s->response_body.kind = kHpsBodyDone;
            if (s->child_eof && ! s->deferred[1] && needs_input && ! s->again &&
                (s->response_header || s->response_body.kind != kHpsBodyDone))
            {
                fail(s, 502);
                s->again = true;
                continue;
            }
            if (! s->response_header && s->response_body.kind == kHpsBodyDone && ! s->output[1])
            {
                if (s->input[1] || s->deferred[1])
                {
                    fail(s, 502);
                    s->again = true;
                    continue;
                }
                if (s->close_after || s->upload_stopped)
                {
                    hpsClose(s, false);
                    break;
                }
                if (s->request_body.kind == kHpsBodyDone && ! s->output[0] && ! s->receiving_down)
                {
                    if (! s->child_reusable)
                        hpsCloseChild(s, false);
                    s->phase           = kHpsRequest;
                    s->final_committed = false;
                    s->again           = true;
                }
            }
        }
        pressure(s);
    } while (s->again);
    s->pumping = false;
}

static void timeout(wtimer_t *timer)
{
    hps_session_t *s = weventGetUserdata(timer);
    hpsRetain(s);
    uint64_t now   = nowMs();
    unsigned error = 0;
    if (s->header_at[0] && now - s->header_at[0] >= settings(s)->header_timeout)
        error = 408;
    else if (s->header_at[1] && now - s->header_at[1] >= settings(s)->header_timeout)
        error = 504;
    else if (s->connect_at && now - s->connect_at >= settings(s)->connect_timeout)
        error = 504;
    else if (now - s->progress_at >= settings(s)->idle_timeout)
    {
        if (s->phase == kHpsRequest && ! s->input[0])
            hpsClose(s, false);
        else
            error = 504;
    }
    if (error)
    {
        fail(s, error);
        pump(s);
    }
    hpsRelease(s);
}

void hpsInit(tunnel_t *t, line_t *l)
{
    hps_tstate_t *ts = tunnelGetState(t);
    hps_lstate_t *ls = lineGetState(l, t);
    *ls              = (hps_lstate_t) {.line = l};
    hps_session_t *s = memoryAllocateZero(sizeof(*s));
    if (! s || ts->workers[lineGetWID(l)].quiescing)
    {
        memoryFree(s);
        clearSlot(l, t);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    s->t           = t;
    s->client      = l;
    s->references  = 1;
    s->progress_at = nowMs();
    lineRef(l);
    ls->session = s;
    hpsRetain(s);
    uint32_t interval = min(1000, min(ts->header_timeout, min(ts->connect_timeout, ts->idle_timeout)));
    s->timer          = wtimerAdd(getCurrentEventWorkerLoop(), timeout, interval, INFINITE);
    if (! s->timer)
        hpsClose(s, false);
    else
    {
        hps_worker_t *w = &ts->workers[lineGetWID(l)];
        s->timer_next   = w->timers;
        if (s->timer_next)
            s->timer_next->timer_prev = s;
        w->timers = s;
        weventSetUserData(s->timer, s);
    }
    hpsRelease(s);
}

void hpsFinish(tunnel_t *t, line_t *l, bool child)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    assert(s && ls->child == child);
    hpsRetain(s);
    if (! child)
        hpsClose(s, true);
    else
    {
        hpsCloseChild(s, true); /* The owned child is logically dead before any client-side continuation. */
        s->child_eof = true;
        if (s->phase == kHpsRelay)
            hpsClose(s, false);
        else if (s->phase == kHpsConnect)
            fail(s, 502);
        pump(s);
    }
    hpsRelease(s);
}

void hpsPayload(tunnel_t *t, line_t *l, sbuf_t *buf, unsigned d)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hps_tstate_t  *ts = tunnelGetState(t);
    if (! s || ts->workers[lineGetWID(l)].quiescing)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    hpsRetain(s);
    lineRef(l);
    if (d == 1)
        ++s->receiving_down;
    const uint64_t allowance = kHpsDeliveryHeadroomBytes;
    const bool     oversized = (uint64_t) sbufGetLength(buf) > allowance + settings(s)->max_pending;
    /* Preserve streaming of larger callbacks when their prefix can make immediate
     * progress. Only the retained remainder consumes delivery headroom. */
    while (
        ! oversized && sbufGetLength(buf) > allowance && active(s) && ! s->deferred[d] && ! s->paused[d] &&
        s->phase != kHpsError &&
        ! (d == 0 && (s->upload_stopped || s->phase == kHpsConnect ||
                      (s->phase == kHpsExchange && (! s->child_established || s->request_body.kind == kHpsBodyDone)))))
    {
        size_t room = settings(s)->max_pending - pending(s);
        if ((d == 0 ? s->phase == kHpsRequest : s->response_header) && room > 1024)
            room -= 1024;
        size_t n = min((size_t) 16384, room);
        if (! n || ! appendInput(s, d, sbufGetRawPtr(buf), n))
            break;
        sbufShiftRight(buf, (uint32_t) n);
        pump(s);
    }
    const uint64_t length = sbufGetLength(buf);
    const uint64_t older  = s->deferred[d] ? sbufGetLength(s->deferred[d]) : 0;
    if (! active(s) || (d == 0 && s->upload_stopped) || s->phase == kHpsError)
        lineReuseBuffer(l, buf);
    else if (oversized || length + older > allowance)
    {
        lineReuseBuffer(l, buf);
        fail(s, 503);
    }
    else if (length != 0)
    {
        /* Use bounded best-fit storage at admission instead of retaining an
         * arbitrarily oversized carrier allocation. Working storage is charged
         * separately; this slot is at most aligned(max(small, 2*D)) plus padding. */
        sbuf_t *remainder = makeBuffer(s, (size_t) (length + older));
        if (! remainder || ! remainderAllocationFits(s, remainder))
        {
            if (remainder)
                lineReuseBuffer(l, remainder);
            lineReuseBuffer(l, buf);
            fail(s, 503);
        }
        else
        {
            if (older)
                sbufMoveTo(remainder, s->deferred[d], (uint32_t) older);
            sbufMoveTo(remainder, buf, (uint32_t) length);
            lineReuseBuffer(l, buf);
            discardBuffer(s, &s->deferred[d]);
            s->deferred[d] = remainder;
        }
    }
    else
        lineReuseBuffer(l, buf);
    if (d == 1)
        --s->receiving_down;
    if (active(s))
        pump(s);
    lineUnref(l);
    hpsRelease(s);
}

void hpsPressure(tunnel_t *t, line_t *l, unsigned d, bool paused)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hpsRetain(s);
    lineRef(l);
    s->paused[d] = paused;
    pressure(s);
    pump(s);
    lineUnref(l);
    hpsRelease(s);
}

void hpsEstablished(tunnel_t *t, line_t *l)
{
    hps_lstate_t  *ls = lineGetState(l, t);
    hps_session_t *s  = ls->session;
    hpsRetain(s);
    lineRef(l);
    s->child_established = true;
    s->connect_at        = 0;
    s->progress_at       = nowMs();
    if (! s->established)
    {
        s->established = true;
        tunnelPrevDownStreamEst(t, s->client);
    }
    if (active(s))
        pump(s);
    lineUnref(l);
    hpsRelease(s);
}
