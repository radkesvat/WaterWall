/*
 * Covers: shared fallback replay ownership, bounded admission, FIFO scheduling and representation-aware batches.
 * Setup: Real FallbackReplay with the existing worker, normal-line, buffer ledger and delayed-task fixtures.
 * The fixture owns the normal line; FallbackReplay borrows it. No real timer or network endpoint is required.
 * Cases: moved unbound/bound transcripts; pressure compaction with shared budgets; byte/charge/entry refusal;
 * initial inline and reentrant async replay;
 * scheduler refusal; retired/dead queued tasks; mixed ordinary/private-pipe inputs and ordinary merge fallback.
 * Checks: exact replay bytes, callback counts, budget settlement, line-reference settlement and buffer ownership.
 * Limits: Component tests do not establish server authentication, host-network behavior or performance.
 * CTest: waterwall.fallback_replay_unit
 */
#include "FallbackReplay/fallback_replay.h"

#include "fixtures/protocols/fallback_finish_lifetime_fixture.h"
#include "fixtures/protocols/splice_source.h"
#include "wfrand.h"

typedef struct replay_test_state_s
{
    fallback_replay_t replay;
    buffer_budget_t   budget;
    buffer_budget_t   original_budget;
} replay_test_state_t;

typedef struct replay_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    fallback_finish_fixture_t branch;
    fallback_replay_config_t  config;
    tunnel_t                 *node;
    line_t                   *line;
    fallback_replay_result_e  task_result;
    unsigned                  task_calls;
    unsigned                  callback_depth;
    unsigned                  max_callback_depth;
    bool                      inject_payload;
    bool                      require_ordinary;
    sbuf_t                   *expected_buffer;
} replay_fixture_t;

static void replayTask(tunnel_t *owner, line_t *line);

static replay_test_state_t *replayState(replay_fixture_t *fixture)
{
    return lineGetState(fixture->line, fixture->node);
}

static sbuf_t *ordinary(replay_fixture_t *fixture, const char *text)
{
    const uint32_t length = (uint32_t) stringLength(text);
    sbuf_t        *buffer =
        bufferpoolGetBestFit(fixture->env.pool, length, bufferpoolGetLargeBufferPadding(fixture->env.pool));
    sbufWrite(buffer, text, length);
    sbufSetLength(buffer, length);
    return buffer;
}

static sbuf_t *largeOrdinary(replay_fixture_t *fixture, const char *text)
{
    const uint32_t length = (uint32_t) stringLength(text);
    sbuf_t        *buffer = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufWrite(buffer, text, length);
    sbufSetLength(buffer, length);
    return buffer;
}

static void capturePayload(tunnel_t *branch, line_t *line, sbuf_t *buffer)
{
    fallback_finish_fixture_t *capture = fallbackFinishFixture(branch);
    replay_fixture_t          *fixture = *(replay_fixture_t **) tunnelGetState(capture->node);
    const uint32_t             length  = sbufGetLength(buffer);

    ++fixture->callback_depth;
    fixture->max_callback_depth = max(fixture->max_callback_depth, fixture->callback_depth);

    twfRequire(length < sizeof(capture->received) - capture->received_len, "replay capture overflowed");
    if (fixture->require_ordinary)
        twfRequire(! sbufIsSplice(buffer), "exhausted splice inventory did not select ordinary merge");
    if (fixture->expected_buffer != NULL)
        twfRequire(buffer == fixture->expected_buffer, "sole suitable buffer was unnecessarily replaced");
    sbufReadRangeToMemory(buffer, capture->received + capture->received_len, length);
    capture->received_len += length;
    ++capture->payload_calls;
    lineReuseBuffer(line, buffer);

    if (fixture->inject_payload)
    {
        fixture->inject_payload = false;
        const unsigned calls    = capture->payload_calls;
        twfRequire(fallbackReplaySubmit(
                       &replayState(fixture)->replay, fixture->node, line, ordinary(fixture, "-nested"), replayTask) ==
                       kFallbackReplayOk,
                   "reentrant input was refused");
        const bool nested_inline =
            fixture->config.delay_ms == 0 && fixture->config.zero_delay_mode == kFallbackReplayInlineNested;
        twfRequireEqualU32(capture->payload_calls,
                           calls + (nested_inline ? 1 : 0),
                           "nested input did not follow the configured dispatch policy");
        twfRequire(! g_fallback_finish_task.pending, "nested input scheduled before dispatch completed");
    }
    --fixture->callback_depth;
}

static void replayTask(tunnel_t *owner, line_t *line)
{
    replay_fixture_t    *fixture = *(replay_fixture_t **) tunnelGetState(owner);
    replay_test_state_t *state   = lineGetState(line, owner);
    ++fixture->task_calls;
    fixture->task_result = fallbackReplayOnTask(&state->replay, owner, line, replayTask);
}

static void setup(replay_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, 64 * 1024, 64);
    fallbackFinishResetScheduledTask();
    fixture->config = (fallback_replay_config_t) {.delay_ms = 7, .max_batch_bytes = 1024};
    fixture->node   = tunnelCreate(NULL, sizeof(replay_fixture_t *), sizeof(replay_test_state_t));
    twfRequire(fixture->node != NULL, "failed to construct replay fixture owner");
    *(replay_fixture_t **) tunnelGetState(fixture->node) = fixture;
    fixture->branch.node                                 = fixture->node;
    fallbackFinishCreateBranch(&fixture->branch);
    fixture->branch.fallback->fnPayloadU = capturePayload;
    twfLinePoolSetup(&fixture->lines, fixture->node->lstate_size, 4);
    fixture->line                     = twfLinePoolCreateLine(&fixture->lines);
    replay_test_state_t       *state  = replayState(fixture);
    const buffer_budget_cost_t limits = {.bytes = 1024, .charge = SIZE_MAX, .entries = 1024};
    bufferbudgetInit(&state->budget, limits);
    bufferbudgetInit(&state->original_budget, limits);
}

static void destroyReplay(replay_fixture_t *fixture)
{
    replay_test_state_t *state = replayState(fixture);
    fallbackReplayDestroy(&state->replay, fixture->env.pool);
    bufferbudgetAssertEmpty(&state->budget);
    bufferbudgetAssertEmpty(&state->original_budget);
}

static void teardown(replay_fixture_t *fixture)
{
    twfRequire(! g_fallback_finish_task.pending, "fixture retained a scheduled task");
    if (fixture->line != NULL)
    {
        destroyReplay(fixture);
        twfRequireEqualU32(twfLineRefCount(fixture->line), 1, "replay retained an unexpected line reference");
        memoryZeroAligned32(replayState(fixture), fixture->node->lstate_size);
        lineDestroy(fixture->line);
    }
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->branch.fallback);
    tunnelDestroy(fixture->node);
    twfWorkerEnvTeardown(&fixture->env);
}

static fallback_replay_result_e begin(replay_fixture_t *fixture, buffer_queue_t *transcript)
{
    replay_test_state_t *state = replayState(fixture);
    return fallbackReplayBegin(
        &state->replay, fixture->line, fixture->branch.fallback, &fixture->config, &state->budget, transcript);
}

static fallback_replay_result_e initialized(replay_fixture_t *fixture)
{
    tunnelUpStreamInit(fixture->branch.fallback, fixture->line);
    fallbackReplayMarkInitialized(&replayState(fixture)->replay);
    return fallbackReplayInitDone(&replayState(fixture)->replay, fixture->node, fixture->line, replayTask);
}

static void requireMoved(buffer_queue_t *transcript)
{
    twfRequire(bufferqueueGetBufCount(transcript) == 0 && bufferqueueGetBufLen(transcript) == 0 &&
                   bufferqueueGetCharge(transcript) == 0 && transcript->budget == NULL,
               "Begin did not consume and unbind its source transcript");
    bufferqueueDestroy(transcript);
}

static void caseTranscriptBudgetTransfer(unsigned binding)
{
    twfSetCase(binding == 0   ? "unbound transcript admission"
               : binding == 1 ? "already-bound transcript moves without double charging"
                              : "transcript rebind transfers its existing budget charge");
    replay_fixture_t fixture;
    setup(&fixture);
    replay_test_state_t *state = replayState(&fixture);
    buffer_queue_t       transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "one"));
    bufferqueuePushBack(&transcript, ordinary(&fixture, "-two"));
    const size_t charge = bufferqueueGetCharge(&transcript);
    bufferbudgetInit(&state->budget, (buffer_budget_cost_t) {.bytes = 7, .charge = charge, .entries = 2});
    fixture.config.max_batch_bytes = 7;
    if (binding != 0)
        twfRequire(bufferqueueTryAttachBudget(&transcript, binding == 1 ? &state->budget : &state->original_budget),
                   "fixture failed to bind its original transcript");

    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "exact-limit transcript was refused");
    requireMoved(&transcript);
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&state->budget);
    twfRequire(usage.bytes == 7 && usage.charge == charge && usage.entries == 2, "moved transcript accounting changed");
    bufferbudgetAssertEmpty(&state->original_budget);
    twfRequireEqualU32(fixture.branch.payload_calls, 0, "Begin delivered before branch Init");
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "initialized transcript could not schedule");
    twfRequire(g_fallback_finish_task.pending && g_fallback_finish_task.delay_ms == 7,
               "positive-delay transcript did not retain one delayed task");
    fallbackFinishDriveDelayedTask();
    twfRequire(fixture.task_result == kFallbackReplayOk, "scheduled transcript failed");
    twfRequireEqualText((const char *) fixture.branch.received, "one-two", "moved transcript lost FIFO bytes");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "transcript was not merged into one batch");
    bufferbudgetAssertEmpty(&state->budget);
    teardown(&fixture);
}

static void caseBeginRefusal(unsigned limit)
{
    twfSetCase(limit == 0   ? "Begin consumes oversized transcript"
               : limit == 1 ? "Begin consumes transcript exceeding allocation charge"
               : limit == 2 ? "Begin consumes transcript exceeding entry allowance"
                            : "Begin consumes rejected transcript bound to another budget");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.compact_ordinary = true;
    replay_test_state_t *state = replayState(&fixture);
    buffer_queue_t       transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "12345"));
    buffer_budget_cost_t limits = {.bytes = 1024, .charge = SIZE_MAX, .entries = 1024};
    if (limit == 0)
        fixture.config.max_batch_bytes = 4;
    else if (limit == 1)
        limits.charge = bufferqueueGetCharge(&transcript) - 1;
    else
        limits.entries = 0;
    bufferbudgetInit(&state->budget, limits);
    if (limit == 3)
        twfRequire(bufferqueueTryAttachBudget(&transcript, &state->original_budget), "fixture transcript bind failed");
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayRefused, "over-limit Begin was accepted");
    requireMoved(&transcript);
    bufferbudgetAssertEmpty(&state->budget);
    bufferbudgetAssertEmpty(&state->original_budget);
    twfRequireNoLeakedBuffers();
    twfRequire(! g_fallback_finish_task.pending, "refused transcript scheduled a callback");
    teardown(&fixture);
}

static void caseSubmitRefusal(unsigned limit, bool zero_delay)
{
    twfSetCase(limit == 0   ? "Submit refuses byte limit plus one"
               : limit == 1 ? "Submit refuses charge limit plus one buffer"
                            : "Submit refuses entry limit plus one");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.compact_ordinary = zero_delay;
    if (zero_delay)
        fixture.config.delay_ms = 0;
    replay_test_state_t *state  = replayState(&fixture);
    sbuf_t              *first  = ordinary(&fixture, "1234");
    buffer_budget_cost_t limits = {.bytes = 1024, .charge = SIZE_MAX, .entries = 1024};
    if (limit == 0)
        fixture.config.max_batch_bytes = 4;
    else if (limit == 1)
        limits.charge = sbufGetQueueCharge(first);
    else
        limits.entries = 1;
    bufferbudgetInit(&state->budget, limits);
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "empty transcript was refused");
    requireMoved(&transcript);
    twfRequire(fallbackReplaySubmit(&state->replay, fixture.node, fixture.line, first, replayTask) == kFallbackReplayOk,
               "exact-limit retained input was refused");
    twfRequire(fallbackReplaySubmit(&state->replay, fixture.node, fixture.line, ordinary(&fixture, "5"), replayTask) ==
                   kFallbackReplayRefused,
               "over-limit retained input was accepted");
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&state->budget);
    twfRequire(usage.bytes == 4 && usage.entries == 1, "refusal changed earlier retained input accounting");
    twfRequire(! g_fallback_finish_task.pending, "input scheduled before Init completed");
    teardown(&fixture);
}

static void caseCompactTranscript(bool bound, bool entry_pressure, bool refuse)
{
    twfSetCase(entry_pressure ? "compact transcript at entry pressure" : "compact transcript at charge pressure");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.compact_ordinary = true;
    replay_test_state_t *state      = replayState(&fixture);
    buffer_queue_t       transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, largeOrdinary(&fixture, "one"));
    bufferqueuePushBack(&transcript, largeOrdinary(&fixture, "-two"));
    if (bound)
        twfRequire(bufferqueueTryAttachBudget(&transcript, &state->original_budget), "transcript bind failed");

    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(fixture.env.pool, 7, bufferpoolGetLargeBufferPadding(fixture.env.pool), &fit),
               "compact geometry query failed");
    const buffer_budget_cost_t other = {11, 17, 2};
    bufferbudgetInit(
        &state->budget,
        (buffer_budget_cost_t) {7 + other.bytes,
                                entry_pressure ? SIZE_MAX : fit.allocation_charge + other.charge - (refuse ? 1 : 0),
                                entry_pressure ? 1 + other.entries : 1024});
    twfRequire(bufferbudgetTryAcquire(&state->budget, other), "other budget owner could not reserve");

    const fallback_replay_result_e result = begin(&fixture, &transcript);
    twfRequire(result == (refuse ? kFallbackReplayRefused : kFallbackReplayOk), "compact transcript admission wrong");
    requireMoved(&transcript);
    bufferbudgetAssertEmpty(&state->original_budget);
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&state->budget);
    if (refuse)
    {
        twfRequire(usage.bytes == other.bytes && usage.charge == other.charge && usage.entries == other.entries,
                   "refused compaction consumed another owner's allowance");
        bufferbudgetRelease(&state->budget, other);
        teardown(&fixture);
        return;
    }
    twfRequire(usage.bytes == 7 + other.bytes && usage.charge == fit.allocation_charge + other.charge &&
                   usage.entries == 1 + other.entries,
               "compaction lost shared budget accounting");
    twfRequire(sbufGetLeftCapacity(bufferqueueFront(&state->replay.pending)) >=
                   bufferpoolGetLargeBufferPadding(fixture.env.pool),
               "compaction lost onward padding");
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "compact transcript scheduling failed");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualText((const char *) fixture.branch.received, "one-two", "compaction changed transcript FIFO");
    bufferbudgetRelease(&state->budget, other);
    teardown(&fixture);
}

static void caseCompactSubmit(unsigned pressure)
{
    twfSetCase(pressure == 0   ? "compact pending plus incoming at charge pressure"
               : pressure == 1 ? "compact pending plus incoming at entry pressure"
                               : "compact sole oversized incoming allocation");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.compact_ordinary = true;
    replay_test_state_t *state      = replayState(&fixture);
    sbuf_t              *first      = largeOrdinary(&fixture, "one");
    buffer_pool_fit_t    fit;
    twfRequire(bufferpoolQueryBestFit(fixture.env.pool, 7, bufferpoolGetLargeBufferPadding(fixture.env.pool), &fit),
               "compact geometry query failed");
    bufferbudgetInit(&state->budget,
                     (buffer_budget_cost_t) {1024,
                                             pressure == 0   ? sbufGetQueueCharge(first)
                                             : pressure == 1 ? SIZE_MAX
                                                             : fit.allocation_charge,
                                             pressure == 1 ? 1 : 1024});
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "empty transcript failed");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "empty replay initialization failed");
    twfRequire(fallbackReplaySubmit(&state->replay, fixture.node, fixture.line, first, replayTask) == kFallbackReplayOk,
               "first compactable input was refused");
    const uint32_t delay = g_fallback_finish_task.delay_ms;
    twfRequire(g_fallback_finish_task.pending, "first input did not schedule");
    twfRequire(
        fallbackReplaySubmit(&state->replay, fixture.node, fixture.line, largeOrdinary(&fixture, "-two"), replayTask) ==
            kFallbackReplayOk,
        "compactable new input was refused");
    twfRequire(g_fallback_finish_task.pending && g_fallback_finish_task.delay_ms == delay,
               "compaction changed the existing deadline");
    const buffer_budget_cost_t usage = bufferbudgetGetUsage(&state->budget);
    twfRequire(usage.bytes == 7 && usage.charge == fit.allocation_charge && usage.entries == 1,
               "compaction did not replace retained allocations");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualText((const char *) fixture.branch.received, "one-two", "submit compaction changed FIFO");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "compaction dispatched before its scheduled batch");
    teardown(&fixture);
}

static void caseInitialAndReentrantZeroDelay(void)
{
    twfSetCase("initial zero-delay batch is inline; nested and later bytes stay FIFO behind async drain");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.delay_ms = 0;
    fixture.inject_payload  = true;
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "initial"));
    bufferqueuePushBack(&transcript, ordinary(&fixture, "-tail"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "zero-delay transcript was refused");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "initial zero-delay delivery failed");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "initial transcript did not run inline as one batch");
    twfRequireEqualText((const char *) fixture.branch.received, "initial-tail", "initial transcript changed");
    twfRequire(g_fallback_finish_task.pending && g_fallback_finish_task.delay_ms == 0,
               "nested retained bytes did not schedule asynchronous zero-delay drain");
    twfRequire(
        fallbackReplaySubmit(
            &replayState(&fixture)->replay, fixture.node, fixture.line, ordinary(&fixture, "-later"), replayTask) ==
            kFallbackReplayOk,
        "later input behind scheduled drain was refused");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "later input overtook nested retained bytes");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.branch.payload_calls, 2, "retained input was not merged into one later batch");
    twfRequireEqualText((const char *) fixture.branch.received, "initial-tail-nested-later", "nested FIFO changed");
    twfRequire(! g_fallback_finish_task.pending, "completed FIFO left a spurious drain");
    teardown(&fixture);
}

static void caseCallerDrivenZeroDelay(void)
{
    twfSetCase("caller-driven zero delay preserves queued entry boundaries without scheduling");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.delay_ms        = 0;
    fixture.config.zero_delay_mode = kFallbackReplayCallerDriven;
    fixture.inject_payload         = true;
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "initial"));
    bufferqueuePushBack(&transcript, ordinary(&fixture, "-tail"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "caller-driven transcript refused");
    requireMoved(&transcript);
    bool dispatched = true;
    twfRequire(
        fallbackReplayDrainOne(&replayState(&fixture)->replay, fixture.node, fixture.line, replayTask, &dispatched) ==
                kFallbackReplayOk &&
            ! dispatched,
        "caller pump delivered before Init completed");
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "caller-driven initial batch failed");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "initial replay was not one inline batch");
    twfRequire(! g_fallback_finish_task.pending, "caller-driven reentry scheduled a zero-delay task");
    twfRequire(
        fallbackReplaySubmit(
            &replayState(&fixture)->replay, fixture.node, fixture.line, ordinary(&fixture, "-later"), replayTask) ==
            kFallbackReplayOk,
        "caller-driven later input refused");
    for (unsigned i = 0; i < 2; ++i)
    {
        twfRequire(fallbackReplayDrainOne(
                       &replayState(&fixture)->replay, fixture.node, fixture.line, replayTask, &dispatched) ==
                           kFallbackReplayOk &&
                       dispatched,
                   "caller-driven FIFO did not advance");
        twfRequireEqualU32(fixture.branch.payload_calls, i + 2, "caller-driven drain merged separate entries");
    }
    twfRequire(
        fallbackReplayDrainOne(&replayState(&fixture)->replay, fixture.node, fixture.line, replayTask, &dispatched) ==
                kFallbackReplayOk &&
            ! dispatched,
        "empty caller-driven FIFO dispatched a payload");
    twfRequireEqualText(
        (const char *) fixture.branch.received, "initial-tail-nested-later", "caller-driven FIFO changed");
    twfRequireEqualU32(fixture.max_callback_depth, 1, "caller-driven input recursively entered Payload");
    twfRequire(! g_fallback_finish_task.pending, "caller-driven drain scheduled a zero-delay task");
    teardown(&fixture);
}

static void caseNestedInlineZeroDelay(void)
{
    twfSetCase("inline-nested zero delay preserves recursive callback completion");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.delay_ms        = 0;
    fixture.config.zero_delay_mode = kFallbackReplayInlineNested;
    fixture.inject_payload         = true;
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "initial"));
    bufferqueuePushBack(&transcript, ordinary(&fixture, "-tail"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "nested-inline transcript refused");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "nested-inline initial batch failed");
    twfRequireEqualU32(fixture.branch.payload_calls, 2, "nested-inline input did not complete within the initial send");
    twfRequireEqualU32(fixture.max_callback_depth, 2, "nested-inline callback did not preserve nesting");
    twfRequireEqualText((const char *) fixture.branch.received, "initial-tail-nested", "nested-inline FIFO changed");
    twfRequire(! g_fallback_finish_task.pending, "nested-inline input scheduled a zero-delay task");
    teardown(&fixture);
}

static void casePositiveDelayMode(fallback_replay_zero_delay_mode_e mode)
{
    twfSetCase(mode == kFallbackReplayCallerDriven ? "caller-driven mode retains positive-delay batching"
                                                   : "inline-nested mode retains positive-delay batching");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.zero_delay_mode = mode;
    fixture.inject_payload         = true;
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "initial"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "delayed transcript refused");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "delayed transcript failed");
    twfRequireEqualU32(fixture.branch.payload_calls, 0, "positive delay delivered inline");
    twfRequire(g_fallback_finish_task.pending && g_fallback_finish_task.delay_ms == 7,
               "positive delay did not schedule its batch");
    if (mode == kFallbackReplayCallerDriven)
    {
        bool dispatched;
        twfRequire(fallbackReplayDrainOne(
                       &replayState(&fixture)->replay, fixture.node, fixture.line, replayTask, &dispatched) ==
                           kFallbackReplayOk &&
                       ! dispatched,
                   "caller pump bypassed a positive delay");
    }
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "positive-delay reentry ran before its timer");
    twfRequire(g_fallback_finish_task.pending && g_fallback_finish_task.delay_ms == 7,
               "positive-delay reentry did not schedule its next batch");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.branch.payload_calls, 2, "positive-delay reentry did not deliver once");
    twfRequireEqualU32(fixture.max_callback_depth, 1, "positive-delay input recursively entered Payload");
    twfRequireEqualText((const char *) fixture.branch.received, "initial-nested", "delayed FIFO changed");
    teardown(&fixture);
}

static void caseSchedulerRefusal(void)
{
    twfSetCase("scheduler refusal preserves owned bytes until node cleanup");
    replay_fixture_t fixture;
    setup(&fixture);
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "retained"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "transcript was refused before scheduling");
    requireMoved(&transcript);
    g_fallback_finish_task.refuse = true;
    twfRequire(initialized(&fixture) == kFallbackReplayRefused, "scheduling refusal was not reported");
    twfRequireEqualU32(fixture.branch.payload_calls, 0, "refused timer delivered bytes inline");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "refused timer retained its line reference");
    twfRequire(bufferbudgetGetUsage(&replayState(&fixture)->budget).bytes == 8,
               "scheduling refusal abandoned owned replay bytes");
    teardown(&fixture);
}

static void caseJitteredBatch(void)
{
    twfSetCase("jitter samples one bounded delay for the complete pending batch");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.jitter_ms = 2;
    twfRequire(globalstateInitializeSecureRandom() && frandGlobalInit(), "random initialization failed");
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "jitter"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "jittered transcript was refused");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "jittered batch could not schedule");
    const uint32_t delay = g_fallback_finish_task.delay_ms;
    twfRequire(g_fallback_finish_task.pending && delay >= 5 && delay <= 9,
               "scheduled delay exceeded configured jitter");
    twfRequire(
        fallbackReplaySubmit(
            &replayState(&fixture)->replay, fixture.node, fixture.line, ordinary(&fixture, "-later"), replayTask) ==
            kFallbackReplayOk,
        "later input for jittered batch was refused");
    twfRequireEqualU32(g_fallback_finish_task.delay_ms, delay, "additional input restarted the pending batch delay");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "jittered FIFO did not merge into one batch");
    twfRequireEqualText((const char *) fixture.branch.received, "jitter-later", "jittered batch changed FIFO bytes");
    teardown(&fixture);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
}

static void caseLateTask(bool dead_line)
{
    twfSetCase(dead_line ? "scheduled task canceled after owner line death" : "late task after replay retirement");
    replay_fixture_t fixture;
    setup(&fixture);
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    bufferqueuePushBack(&transcript, ordinary(&fixture, "discard"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "late-task transcript was refused");
    requireMoved(&transcript);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "late-task scheduling failed");
    destroyReplay(&fixture);
    if (dead_line)
    {
        memoryZeroAligned32(replayState(&fixture), fixture.node->lstate_size);
        lineDestroy(fixture.line);
        fixture.line = NULL;
    }
    fallbackFinishDriveDelayedTask();
    twfRequireEqualU32(fixture.task_calls, dead_line ? 0 : 1, "late-task dispatch did not respect logical life");
    if (! dead_line)
        twfRequire(fixture.task_result == kFallbackReplayGone, "retired replay did not report Gone to a late task");
    twfRequireEqualU32(fixture.branch.payload_calls, 0, "retired replay delivered discarded bytes");
    teardown(&fixture);
}

#if WW_HAVE_SPLICE
static sbuf_t *pipePayload(replay_fixture_t *fixture)
{
    static const char prefix[] = "pipe-";
    static const char body[]   = "body";
    const uint16_t    padding  = bufferpoolGetLargeBufferPadding(fixture->env.pool);
    sbuf_t           *buffer   = twfTrackAcquired(testSpliceSourceBuffer(padding + 32, sizeof(body) - 1));
    twfRequire(write(sbufSpliceMetadata(buffer).pipefd[1], body, sizeof(body) - 1) == sizeof(body) - 1,
               "failed to populate fixture's private pipe body");
    buffer->capacity = buffer->l_pad + sizeof(body) - 1;
    sbufSetLength(buffer, sizeof(body) - 1);
    sbufShiftLeft(buffer, sizeof(prefix) - 1);
    memoryCopy(sbufGetMutablePtr(buffer), prefix, sizeof(prefix) - 1);
    return buffer;
}

static void caseSpliceBatch(bool force_ordinary, bool sole)
{
    twfSetCase(sole             ? "sole suitable splice transcript preserves identity"
               : force_ordinary ? "mixed batch preserves bytes with exhausted destination inventory"
                                : "mixed ordinary and resident-prefix private-pipe transcript");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.delay_ms  = 0;
    fixture.require_ordinary = force_ordinary;
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    if (! sole)
        bufferqueuePushBack(&transcript, ordinary(&fixture, "before-"));
    sbuf_t *pipe = pipePayload(&fixture);
    bufferqueuePushBack(&transcript, pipe);
    if (sole)
        fixture.expected_buffer = pipe;
    else
        bufferqueuePushBack(&transcript, ordinary(&fixture, "-after"));
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "mixed transcript admission failed");
    requireMoved(&transcript);
    test_splice_inventory_hold_t held = {0};
    if (force_ordinary)
        held = testSpliceInventoryHoldAvailable(fixture.env.pool);
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "mixed transcript replay failed");
    twfRequireEqualU32(fixture.branch.payload_calls, 1, "mixed transcript emitted more than one batch");
    twfRequireEqualText((const char *) fixture.branch.received,
                        sole ? "pipe-body" : "before-pipe-body-after",
                        "mixed transcript corrupted resident prefix or private body");
    testSpliceInventoryReleaseHeld(&held);
    teardown(&fixture);
}

static void caseSplicePressure(void)
{
    twfSetCase("ordinary compaction never materializes a retained splice batch");
    replay_fixture_t fixture;
    setup(&fixture);
    fixture.config.compact_ordinary = true;
    replay_test_state_t *state      = replayState(&fixture);
    bufferbudgetInit(&state->budget, (buffer_budget_cost_t) {1024, SIZE_MAX, 1});
    buffer_queue_t transcript;
    bufferqueueInitEmpty(&transcript);
    sbuf_t *pipe = pipePayload(&fixture);
    bufferqueuePushBack(&transcript, pipe);
    twfRequire(begin(&fixture, &transcript) == kFallbackReplayOk, "splice transcript failed");
    requireMoved(&transcript);
    twfRequire(
        fallbackReplaySubmit(&state->replay, fixture.node, fixture.line, ordinary(&fixture, "-tail"), replayTask) ==
            kFallbackReplayRefused,
        "entry pressure converted a splice batch");
    twfRequire(bufferqueueFront(&state->replay.pending) == pipe, "refusal replaced the retained pipe");
    twfRequire(initialized(&fixture) == kFallbackReplayOk, "splice batch scheduling failed");
    fallbackFinishDriveDelayedTask();
    twfRequireEqualText((const char *) fixture.branch.received, "pipe-body", "refusal consumed retained pipe bytes");
    teardown(&fixture);
}
#endif

int main(void)
{
    for (unsigned binding = 0; binding < 3; ++binding)
        caseTranscriptBudgetTransfer(binding);
    for (unsigned limit = 0; limit < 4; ++limit)
        caseBeginRefusal(limit);
    for (unsigned limit = 0; limit < 3; ++limit)
    {
        caseSubmitRefusal(limit, false);
        caseSubmitRefusal(limit, true);
        caseCompactSubmit(limit);
    }
    for (unsigned bound = 0; bound < 2; ++bound)
        for (unsigned entries = 0; entries < 2; ++entries)
            caseCompactTranscript(bound != 0, entries != 0, false);
    caseCompactTranscript(true, false, true);
    caseInitialAndReentrantZeroDelay();
    caseCallerDrivenZeroDelay();
    caseNestedInlineZeroDelay();
    casePositiveDelayMode(kFallbackReplayCallerDriven);
    casePositiveDelayMode(kFallbackReplayInlineNested);
    caseSchedulerRefusal();
    caseJitteredBatch();
    caseLateTask(false);
    caseLateTask(true);
#if WW_HAVE_SPLICE
    caseSpliceBatch(false, true);
    caseSpliceBatch(false, false);
    caseSpliceBatch(true, false);
    caseSplicePressure();
#endif
    printf("fallback_replay_test: all cases passed\n");
    return 0;
}
