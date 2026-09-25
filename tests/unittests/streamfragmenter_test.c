#include "StreamFragmenter/structure.h"
#include "wevent.h"
#include "wloop_internal.h"

#if WW_HAVE_SPLICE
#include <unistd.h>
#endif

static uint64_t        now_us = UINT64_C(1000123456);
static bool            refuse_timer, refuse_pipe, refuse_job;
static unsigned        representation;
static tunnel_t       *fragmenter, *previous, *next;
static node_t          node;
static tunnel_chain_t *chain;
static line_t         *line;
static wloop_t        *loop;
static unsigned        writes, downstream_writes, pauses, resumes, establishments;
static uint32_t        lengths[2048];
static uint64_t        times[2048];
static bool            spliced[2048], source_paused;
static uintptr_t       last_buffer;
static char            output[16384], finishes[8];
static size_t          output_size, finish_count;
static void (*on_payload)(void), (*on_pause)(void), (*on_resume)(void), (*on_est)(void);
static const uint32_t *random_draws;
static size_t          random_count, random_index;

uint64_t __wrap_getHRTimeUs(void);
uint64_t __wrap_getHRTimeUs(void)
{
    return now_us;
}
wtimer_t *__real_wtimerAdd(wloop_t *, wtimer_cb, uint32_t, uint32_t);
wtimer_t *__wrap_wtimerAdd(wloop_t *owner, wtimer_cb cb, uint32_t timeout, uint32_t repeat);
wtimer_t *__wrap_wtimerAdd(wloop_t *owner, wtimer_cb cb, uint32_t timeout, uint32_t repeat)
{
    return refuse_timer ? NULL : __real_wtimerAdd(owner, cb, timeout, repeat);
}
sbuf_t *__real_bufferpoolGetSpliceBuffer(buffer_pool_t *);
sbuf_t *__wrap_bufferpoolGetSpliceBuffer(buffer_pool_t *pool);
sbuf_t *__wrap_bufferpoolGetSpliceBuffer(buffer_pool_t *pool)
{
    return refuse_pipe ? NULL : __real_bufferpoolGetSpliceBuffer(pool);
}
void *__real_memoryAllocateZero(size_t);
void *__wrap_memoryAllocateZero(size_t size);
void *__wrap_memoryAllocateZero(size_t size)
{
    return refuse_job && size == sizeof(streamfragmenter_job_t) ? NULL : __real_memoryAllocateZero(size);
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr,
                "StreamFragmenter: %s (representation=%u, writes=%u, bytes=%zu)\n",
                message,
                representation,
                writes,
                output_size);
        exit(1);
    }
}
static void fireHook(void (**hook)(void))
{
    void (*callback)(void) = *hook;
    *hook                  = NULL;
    if (callback != NULL)
        callback();
}
uint32_t __wrap_fastRand(void);
uint32_t __wrap_fastRand(void)
{
    require(random_index < random_count, "unexpected probability evaluation");
    return random_draws[random_index++];
}
static streamfragmenter_lstate_t *state(void)
{
    return lineGetState(line, fragmenter);
}
static void advance(uint64_t microseconds)
{
    now_us += microseconds;
    require(wloopProcessEvents(loop, 0) >= 0, "event-loop dispatch");
}
static sbuf_t *input(const char *data, uint32_t length)
{
#if WW_HAVE_SPLICE
    if (representation)
    {
        sbuf_t *buf = bufferpoolGetSpliceBuffer(lineGetBufferPool(line));
        require(buf != NULL, "source pipe allocation");
        const uint32_t prefix = representation == 2 ? min(length, 3U) : 0;
        const uint32_t body   = length - prefix;
        if (body)
            require(write(sbufSpliceMetadata(buf).pipefd[1], data + prefix, body) == body, "source pipe contents");
        buf->capacity = buf->l_pad + body;
        buf->len      = body;
        if (prefix)
        {
            sbufShiftLeft(buf, prefix);
            memoryCopy(sbufGetMutablePtr(buf), data, prefix);
        }
        return buf;
    }
#endif
    sbuf_t *buf = bufferpoolGetBestFit(lineGetBufferPool(line), length, 64);
    memoryCopy(sbufGetMutablePtr(buf), data, length);
    sbufSetLength(buf, length);
    return buf;
}
static void sendText(const char *text)
{
    fragmenter->fnPayloadU(fragmenter, line, input(text, (uint32_t) stringLength(text)));
}
static void sourceClose(void)
{
    fragmenter->fnFinU(fragmenter, line);
    require(lineIsAlive(line), "node destroyed its borrowed line");
    lineDestroy(line);
}
static void consumerClose(void)
{
    fragmenter->fnFinD(fragmenter, line);
}
static void consumerPause(void)
{
    fragmenter->fnPauseD(fragmenter, line);
}
static void inject(void)
{
    sendText("NEW");
}
static void resumeThenInject(void)
{
    consumerPause();
    fragmenter->fnResumeD(fragmenter, line);
    inject();
}
static void previousFinish(tunnel_t *t, line_t *l)
{
    discard t;
    finishes[finish_count++] = 'D';
    lineDestroy(l);
}
static void nextFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    finishes[finish_count++] = 'U';
}
static void previousPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pauses;
    source_paused = true;
    fireHook(&on_pause);
}
static void previousResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++resumes;
    source_paused = false;
    fireHook(&on_resume);
}
static void previousEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++establishments;
    fireHook(&on_est);
}
static void nextInit(tunnel_t *t, line_t *l)
{
    discard t;
    fragmenter->fnEstD(fragmenter, l);
}
static void capture(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    require(l == line && lineIsAlive(l), "payload exact live line");
    require(writes < ARRAY_SIZE(lengths), "capture count");
    uint32_t length = sbufGetLength(buf);
    require(length < sizeof(output) - output_size, "capture bytes");
    require(sbufGetLeftCapacity(buf) >= 64, "onward padding lost");
    lengths[writes]   = length;
    times[writes]     = now_us;
    spliced[writes++] = sbufIsSplice(buf);
    last_buffer       = (uintptr_t) buf;
    sbufReadRangeToMemory(buf, output + output_size, length);
    output_size += length;
    output[output_size] = 0;
    lineReuseBuffer(l, buf);
    fireHook(&on_payload);
}
static void captureDownstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    last_buffer = (uintptr_t) buf;
    ++downstream_writes;
    lineReuseBuffer(l, buf);
}
static void openLine(const char *settings)
{
    writes = downstream_writes = pauses = resumes = establishments = 0;
    output_size = finish_count = 0;
    output[0] = finishes[0] = 0;
    source_paused           = false;
    node                    = nodeStreamFragmenterGet();
    node.node_settings_json = cJSON_Parse(settings);
    require(node.node_settings_json != NULL, "fixture JSON");
    fragmenter = streamfragmenterTunnelCreate(&node);
    require(fragmenter != NULL, "valid settings rejected");
    previous = tunnelCreate(NULL, 0, 0);
    next     = tunnelCreate(NULL, 0, 0);
    tunnelBind(previous, fragmenter);
    tunnelBind(fragmenter, next);
    previous->fnFinD     = previousFinish;
    previous->fnPayloadD = captureDownstream;
    previous->fnPauseD   = previousPause;
    previous->fnResumeD  = previousResume;
    previous->fnEstD     = previousEst;
    next->fnInitU        = nextInit;
    next->fnPayloadU     = capture;
    next->fnFinU         = nextFinish;
    chain                = tunnelchainCreate(1);
    tunnelchainInsert(chain, fragmenter);
    /* Model onward padding plus a previous transform's resident prefix. */
    chain->sum_padding_left = 96;
    uint32_t offset         = 0;
    fragmenter->onIndex(fragmenter, 0, &offset);
    tunnelchainFinalize(chain);
    require(chain->supports_splice == (WW_HAVE_SPLICE != 0), "splice capability registration");
    line = lineCreate(chain->line_pools, 0);
    lineRef(line);
    fragmenter->fnInitU(fragmenter, line);
    require(establishments == 1, "Est was held by fragmenter");
}
static void closeLine(void)
{
    if (lineIsAlive(line))
        sourceClose();
    const uint8_t *bytes = (const uint8_t *) state();
    for (uint32_t i = 0; i < fragmenter->lstate_size; ++i)
        require(bytes[i] == 0, "line state not cleared");
    lineUnref(line);
    require(masterpoolGetCheckedOut(chain->masterpool_line_pool) == 0, "line reference leak");
    require(loop->ntimers == 0, "timer leak");
    tunnelDestroy(fragmenter);
    tunnelDestroy(previous);
    tunnelDestroy(next);
    tunnelchainDestroy(chain);
    cJSON_Delete(node.node_settings_json);
    memoryFree(node.type);
    on_payload = on_pause = on_resume = on_est = NULL;
}
static void configuration(void)
{
    const char *invalid[] = {
        "null",
        "[]",
        "{}",
        "{\"mode\":\"other\",\"count\":1,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":1}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"duration-ms\":1}",
        "{\"mode\":\"timed\",\"duration-ms\":1,\"count\":1,\"cuts\":[]}",
        "{\"mode\":\"timed\",\"duration\":\"100ms\",\"cuts\":[]}",
        "{\"mode\":\"timed\",\"duration-ms\":\"100\",\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":1.5,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":-1,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":4294967296,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"bypass_chance\":101}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"bypass_chance\":0.5}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"extra\":0}",
        "{\"mode\":\"counter\",\"count\":1,\"count\":2,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,0]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,0,100,0]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[0,0,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1.5,0,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,-1,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,0.5,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,4294967296,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,0,101]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,0,100],[1,0,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,0,100],[1,0,100]]}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        node_t n = {.node_settings_json = cJSON_Parse(invalid[i])};
        require(streamfragmenterTunnelCreate(&n) == NULL, invalid[i]);
        cJSON_Delete(n.node_settings_json);
    }
    openLine("{\"mode\":\"timed\",\"duration-ms\":4294967295,\"cuts\":[[4294967295,4294967295,100]]}");
    sendText("a");
    require(writes == 1, "maximum integers");
    closeLine();
    char   settings[2048] = "{\"mode\":\"counter\",\"count\":1,\"cuts\":[";
    size_t size           = stringLength(settings);
    for (unsigned i = 1; i <= 64; ++i)
        size += (size_t) snprintf(settings + size, sizeof(settings) - size, "%s[%u,0,100]", i == 1 ? "" : ",", i);
    memcpy(settings + size, "]}", 3);
    openLine(settings);
    char data[66];
    memset(data, 'x', 65);
    data[65] = 0;
    sendText(data);
    require(writes == 65 && output_size == 65, "64th cut mask bit");
    closeLine();
    memcpy(settings + size, ",[65,0,100]]}", sizeof(",[65,0,100]]}"));
    node_t n = {.node_settings_json = cJSON_Parse(settings)};
    require(streamfragmenterTunnelCreate(&n) == NULL, "65 cuts accepted");
    cJSON_Delete(n.node_settings_json);
}
static void boundaries(void)
{
    openLine("{\"mode\":\"counter\",\"count\":3,\"cuts\":[[2,0,100]]}");
    sendText("a");
    sendText("bcde");
    sendText("fg");
    sendText("hijk");
    require(writes == 5 && lengths[0] == 1 && lengths[1] == 2 && lengths[2] == 2 && lengths[3] == 2 && lengths[4] == 4,
            "counter counts arrivals including ignored/equal cuts");
    require(! strcmp(output, "abcdefghijk"), "counter bytes");
    /* A second line in the same instance starts with its own full scope. */
    line_t *first = line;
    line          = lineCreate(chain->line_pools, 0);
    lineRef(line);
    fragmenter->fnInitU(fragmenter, line);
    sendText("lmno");
    require(writes == 7, "per-line independent counter");
    sourceClose();
    lineUnref(line);
    line = first;
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":2,\"bypass_chance\":0,\"cuts\":[[1,0,0],[2,0,100],[3,0,0],[4,0,100],[6,0,"
             "100],[8,0,100]]}");
    sendText("abcdef");
    require(writes == 3 && lengths[0] == 2 && lengths[1] == 2 && lengths[2] == 2, "independent applicable cuts");
    sbuf_t   *down     = input("down", 4);
    uintptr_t original = (uintptr_t) down;
    fragmenter->fnPayloadD(fragmenter, line, down);
    require(downstream_writes == 1 && last_buffer == original, "downstream passthrough");
    closeLine();

    const char *disabled[] = {
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[[1,4,100]]}",
        "{\"mode\":\"timed\",\"duration-ms\":0,\"cuts\":[[1,4,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[]}",
        "{\"mode\":\"counter\",\"count\":1,\"bypass_chance\":100,\"cuts\":[[1,4,100]]}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[1,4,0]]}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(disabled); ++i)
    {
        openLine(disabled[i]);
        sbuf_t *buf = input("unchanged", 9);
        original    = (uintptr_t) buf;
        fragmenter->fnPayloadU(fragmenter, line, buf);
        require(writes == 1 && last_buffer == original && ! state()->head && ! state()->timer, "direct bypass path");
        closeLine();
    }
}
static void timersAndFifo(void)
{
    static const uint32_t draws[] = {99, 0, 0, 99, 99};
    random_draws                  = draws;
    random_count                  = ARRAY_SIZE(draws);
    random_index                  = 0;
    openLine("{\"mode\":\"counter\",\"count\":3,\"bypass_chance\":50,\"cuts\":[[2,5,50]]}");
    sendText("abcd"); /* First bypass fails, cut succeeds. */
    sendText("EFGH"); /* Bypass succeeds, but cannot overtake the first job. */
    sendText("IJKL"); /* Neither bypass nor the cut succeeds. */
    sendText("MNOP"); /* Scope exhausted; no more RNG draws. */
    require(! writes && random_index == random_count, "bypass ordering/counter/random decisions");
    advance(5000);
    require(writes == 5 && lengths[0] == 2 && lengths[1] == 2 && lengths[2] == 4 && lengths[3] == 4 &&
                lengths[4] == 4 && ! strcmp(output, "abcdEFGHIJKLMNOP"),
            "bypassed FIFO jobs");
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":2,\"cuts\":[[2,2,100],[4,5,100]]}");
    uint64_t start = now_us;
    sendText("abcdef");
    sendText("ghijkl");
    sendText("MNOP");
    require(! writes && state()->exhausted, "queued counter exhaustion");
    advance(1999);
    require(! writes, "first delay fired early");
    advance(1);
    require(writes == 1 && lengths[0] == 2 && times[0] == start + 2000, "first cut timing");
    advance(4999);
    require(writes == 1, "second delay fired early");
    advance(1);
    require(writes == 3 && times[1] == start + 7000 && times[2] == times[1], "tail immediately follows last cut");
    advance(1999);
    require(writes == 3, "next job spent its delay behind prior job");
    advance(1);
    require(writes == 4, "next job delay");
    advance(5000);
    require(writes == 7 && ! strcmp(output, "abcdefghijklMNOP"), "draining FIFO byte order");
    sbuf_t   *buf      = input("PASS", 4);
    uintptr_t original = (uintptr_t) buf;
    fragmenter->fnPayloadU(fragmenter, line, buf);
    require(writes == 8 && last_buffer == original && ! state()->head && ! state()->timer, "retired direct path");
    closeLine();

    openLine("{\"mode\":\"timed\",\"duration-ms\":10,\"cuts\":[[2,20,100]]}");
    advance(9999);
    sendText("abcd");
    advance(1);
    sendText("EFGH");
    advance(19999);
    require(writes == 3 && lengths[2] == 4 && ! strcmp(output, "abcdEFGH"), "arrival-time deadline and FIFO");
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,2,100],[4,5,100]]}");
    sendText("abcdef");
    advance(20000);
    require(writes == 1, "late timer incorrectly caught up subsequent cuts");
    advance(5000);
    require(writes == 3, "late timer sequential delay");
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,1000,100]]}");
    start = now_us;
    sendText("abcd");
    /* wtimerAdd rounds some long deadlines down to 100 ms boundaries. */
    advance(999999);
    require(! writes, "coarse timer rounding shortened requested delay");
    advance(1000);
    require(writes == 2 && times[0] >= start + 1000000, "coarse timer rearm");
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,4294967295,100]]}");
    sendText("abcd");
    advance(UINT64_C(4294967295) * 1000 - 1);
    require(! writes, "maximum delay overflowed");
    advance(1000);
    require(writes == 2, "maximum delay failed to expire");
    closeLine();
}
static void pauseAndReentry(void)
{
    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,5,100]]}");
    sendText("abcd");
    advance(2000);
    consumerPause();
    advance(1000);
    fragmenter->fnResumeD(fragmenter, line);
    advance(1999);
    require(! writes, "Resume shortened unexpired delay");
    advance(1);
    require(writes == 2, "Resume restarted unexpired delay");
    closeLine();

    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,2,100],[4,5,100]]}");
    sendText("abcdef");
    consumerPause();
    advance(20000);
    require(! writes && ! state()->timer && source_paused, "due output must wait for Resume");
    on_resume = inject;
    fragmenter->fnResumeD(fragmenter, line);
    require(writes == 1 && ! source_paused, "Resume must release already elapsed delay");
    advance(4999);
    require(writes == 1, "next delay did not start at actual handoff");
    advance(1);
    require(writes == 4 && ! strcmp(output, "abcdefNEW"), "Resume reentry FIFO");
    closeLine();

    void (*actions[])(void) = {inject, resumeThenInject, sourceClose, consumerClose, consumerPause};
    for (size_t i = 0; i < ARRAY_SIZE(actions); ++i)
    {
        openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,0,100],[4,0,100]]}");
        on_payload = actions[i];
        sendText("abcdef");
        if (i < 2)
            require(writes == 4 && ! strcmp(output, "abcdefNEW"), "Payload reentry overtook old suffix");
        else if (i < 4)
            require(! lineIsAlive(line) && writes == 1 && finish_count == 1, "reentrant Finish continued or reflected");
        else
        {
            require(writes == 1, "drain continued after synchronous Pause");
            fragmenter->fnResumeD(fragmenter, line);
            require(writes == 3, "paused suffix lost");
        }
        closeLine();
    }
    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,2,100],[4,5,100]]}");
    on_payload = sourceClose;
    sendText("abcdef");
    advance(2000);
    require(! lineIsAlive(line) && writes == 1, "timer reentrant close");
    closeLine();
    on_est = sourceClose;
    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,2,100]]}");
    require(! lineIsAlive(line), "Init/Est reentrant close");
    closeLine();
}
static void limitsAndCleanup(void)
{
    const char *settings = "{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,60000,100]]}";
    openLine(settings);
    sendText("abcd");
    for (unsigned i = 1; i < kStreamFragmenterHighJobs; ++i)
        sendText("");
    require(source_paused && pauses == 1, "job high watermark");
    consumerPause();
    advance(UINT64_C(60000000));
    require(! writes && resumes == 0, "external pressure must hold expired work");
    on_resume = inject;
    fragmenter->fnResumeD(fragmenter, line);
    require(! source_paused && resumes == 1 && ! strcmp(output, "abcdNEW"), "pressure reasons/hysteresis/FIFO");
    closeLine();

    openLine(settings);
    sendText("abcd");
    for (unsigned i = 1; i < kStreamFragmenterHardJobs; ++i)
        sendText("");
    require(lineIsAlive(line), "inclusive entry hard limit");
    sendText("");
    require(! lineIsAlive(line) && finish_count == 2 && finishes[0] == 'U' && finishes[1] == 'D',
            "overflow close order");
    closeLine();

    openLine(settings);
    sbuf_t *large = bufferpoolGetBestFit(lineGetBufferPool(line), 7 * 1024 * 1024, 64);
    sbufWrite(large, "abcd", 4);
    sbufSetLength(large, 4);
    fragmenter->fnPayloadU(fragmenter, line, large);
    require(source_paused && pauses == 1, "allocation capacity must count, not just four payload bytes");
    large = bufferpoolGetBestFit(lineGetBufferPool(line), 2 * 1024 * 1024, 64);
    fragmenter->fnPayloadU(fragmenter, line, large);
    require(! lineIsAlive(line), "8 MiB capacity limit");
    closeLine();

    for (unsigned failure = 0; failure < 2; ++failure)
    {
        openLine(settings);
        sbuf_t *buf  = input("abcd", 4);
        refuse_timer = failure == 0;
        refuse_job   = failure == 1;
        fragmenter->fnPayloadU(fragmenter, line, buf);
        refuse_timer = refuse_job = false;
        require(! lineIsAlive(line) && ! writes && finish_count == 2, "local resource refusal");
        closeLine();
    }
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        openLine(settings);
        sendText("abcd");
        sendText("later");
        wtimerTestMakePendingOneShot(state()->timer);
        if (direction == 0)
            sourceClose();
        else
            consumerClose();
        advance(UINT64_C(60000000));
        require(! writes && finish_count == 1, "pending timer dispatched after Finish");
        closeLine();
    }
    openLine(settings);
    sendText("abcd");
    on_pause = sourceClose;
    consumerPause();
    require(! lineIsAlive(line), "Pause reentrant close");
    closeLine();
    openLine(settings);
    sendText("abcd");
    consumerPause();
    on_resume = sourceClose;
    fragmenter->fnResumeD(fragmenter, line);
    require(! lineIsAlive(line), "Resume reentrant close");
    closeLine();
}
static void shutdownCleanup(void)
{
    openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,2,100]]}");
    sendText("abcd");
    sendText("later");
    atomicStoreExplicit(&loop->normal_admission_open, false, memory_order_release);
    wloopQuiesceNormalWork(loop);
    require(state()->timer->quiesced && ! writes, "quiescence failed to detach timer");
    closeLine();
}
int main(void)
{
    GSTATE.flag_initialized = true;
    GSTATE.workers_count    = 2;
    GSTATE.splice_disabled  = WW_HAVE_SPLICE == 0;
    master_pool_t *large = masterpoolCreateWithCapacity(8), *medium = masterpoolCreateWithCapacity(8),
                  *small = masterpoolCreateWithCapacity(8), *splice = masterpoolCreateWithCapacity(8),
                  *ios  = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large, medium, small, splice, 4, 4096, 1024, 128, 4096, 4096);
    bufferpoolUpdateAllocationPaddings(pool, 96, 96, 96, 96);
    threadsafe_generic_pool_t *io_pool =
        threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(ios, sizeof(wio_t), 8);
    buffer_pool_t *pool_slots[2] = {pool, pool};
    GSTATE.shortcut_buffer_pools = pool_slots;
    GSTATE.shortcut_wios_pools   = &io_pool;
    loop                         = wloopCreate(0, pool, 0);
    atomicStoreExplicit(&loop->status, WLOOP_STATUS_RUNNING, memory_order_release);
    GSTATE.shortcut_loops = &loop;
    worker_t worker       = {.wid = 0, .buffer_pool = pool, .wios_pool = io_pool, .loop = loop, .has_event_loop = true};
    GSTATE.workers        = &worker;
    testWorkerBindWID(0);
    configuration();
    boundaries();
    timersAndFifo();
    pauseAndReentry();
    limitsAndCleanup();
#if WW_HAVE_SPLICE
    for (representation = 1; representation <= 2; ++representation)
    {
        boundaries();
        timersAndFifo();
        pauseAndReentry();
        limitsAndCleanup();
        openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,0,100],[4,0,100]]}");
        sendText("abcdef");
        require(spliced[0] && spliced[1] && spliced[2], "fragmentation unnecessarily materialized pipe bodies");
        closeLine();
        openLine("{\"mode\":\"counter\",\"count\":1,\"cuts\":[[2,0,100],[4,0,100]]}");
        sbuf_t *buf = input("abcdef", 6);
        refuse_pipe = true;
        fragmenter->fnPayloadU(fragmenter, line, buf);
        refuse_pipe = false;
        require(writes == 3 && ! spliced[0] && ! spliced[1] && ! strcmp(output, "abcdef"), "pipe allocation fallback");
        closeLine();
    }
#endif
    representation = 0;
    shutdownCleanup();
    wloopDestroy(&loop);
    testWorkerUnbindWID();
    threadsafegenericpoolDestroy(io_pool);
    bufferpoolDestroy(pool);
    master_pool_t *pools[] = {large, medium, small, splice, ios};
    for (size_t i = 0; i < ARRAY_SIZE(pools); ++i)
    {
        require(masterpoolGetCheckedOut(pools[i]) == 0, "buffer/pool leak");
        masterpoolMakeEmpty(pools[i]);
        masterpoolDestroy(pools[i]);
    }
    puts("streamfragmenter: passed");
    return 0;
}
