/* A rejected Send admission must stop Hello handling before Report scheduling. */

#include "SpeedTestServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kSpeedServerTestBufferSize = 4096,
};

typedef struct speedtestserver_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  line_pool;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *speed;
    line_t          *line;
} speedtestserver_fixture_t;

static speedtestserver_fixture_t *g_fixture;
static bool                       g_refuse_next_line_task;
static bool                       g_refuse_next_delayed_task;
static bool                       g_forbid_delayed_task;
static unsigned int               g_delayed_task_submissions;

line_task_submit_result_e __real_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __real_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    if (! g_refuse_next_line_task)
    {
        return __real_lineScheduleTask(line, task, t, on_cancel);
    }

    g_refuse_next_line_task = false;
    lineRef(line);
    if (on_cancel != NULL)
    {
        on_cancel(t, line, kLineTaskCancelEnqueueFailure);
    }
    lineUnref(line);
    return kLineTaskSubmitRejectedSettled;
}

line_task_submit_result_e __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel)
{
    g_delayed_task_submissions += 1U;
    if (g_refuse_next_delayed_task)
    {
        g_refuse_next_delayed_task = false;
        lineRef(line);
        if (on_cancel != NULL)
        {
            on_cancel(t, line, kLineTaskCancelResourceFailure);
        }
        lineUnref(line);
        return kLineTaskSubmitRejectedSettled;
    }

    twfRequire(! g_forbid_delayed_task, "SpeedTestServer scheduled Report after Send refusal closed the line");
    return __real_lineScheduleDelayedTask(line, task, delay_ms, t, on_cancel);
}

static void ownerFinish(tunnel_t *prev, line_t *line)
{
    speedtestserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev && line == fixture->line,
               "SpeedTestServer finished an unexpected borrowed line");
    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');
    lineDestroy(line);
}

static void fixtureSetup(speedtestserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kSpeedServerTestBufferSize, 0);

    fixture->prev  = twfCreatePrevTunnel(&fixture->trace);
    fixture->speed = tunnelCreate(NULL, sizeof(speedtestserver_tstate_t), sizeof(speedtestserver_lstate_t));
    twfRequire(fixture->speed != NULL, "failed to create SpeedTestServer fixture tunnel");
    tunnelBind(fixture->prev, fixture->speed);
    fixture->prev->fnFinD = ownerFinish;

    speedtestserver_tstate_t *state = tunnelGetState(fixture->speed);
    state->report_interval_ms       = 1000;
    state->quiet                    = true;
    mutexInit(&state->aggregate_mutex);

    twfLinePoolSetup(&fixture->line_pool, fixture->speed->lstate_size, 4);
    fixture->line = twfLinePoolCreateLine(&fixture->line_pool);
    speedtestserverLinestateInitialize(lineGetState(fixture->line, fixture->speed), fixture->speed, fixture->line);
    g_fixture = fixture;
}

static sbuf_t *makeDownloadHello(speedtestserver_fixture_t *fixture)
{
    const uint32_t frame_size = kSpeedTestServerFrameHeaderSize + kSpeedTestServerHelloSize;
    sbuf_t        *buf        = bufferpoolGetSmallBuffer(fixture->env.pool);
    twfRequire(sbufGetMaximumWriteableSize(buf) >= frame_size, "SpeedTestServer Hello exceeded test buffer");
    sbufSetLength(buf, frame_size);

    uint8_t *frame = sbufGetMutablePtr(buf);
    speedtestserverWriteHeader(frame,
                               kSpeedTestServerFrameHello,
                               kSpeedTestServerFlagDownload | kSpeedTestServerFlagTcp,
                               7,
                               kSpeedTestServerHelloSize,
                               0,
                               0,
                               0,
                               0);

    uint8_t *hello = frame + kSpeedTestServerFrameHeaderSize;
    PUT_BE32(hello + 0, 1000);
    PUT_BE32(hello + 4, 0);
    PUT_BE32(hello + 8, 1000);
    PUT_BE32(hello + 12, 256);
    PUT_BE64(hello + 16, 0);
    PUT_BE32(hello + 24, 1);
    PUT_BE32(hello + 28, 7);
    return buf;
}

static void fixtureTeardownAfterClose(speedtestserver_fixture_t *fixture)
{
    speedtestserver_tstate_t *state = tunnelGetState(fixture->speed);
    mutexDestroy(&state->aggregate_mutex);
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture->line_pool.master),
                       0,
                       "SpeedTestServer fixture retained its borrowed line");
    twfLinePoolTeardown(&fixture->line_pool);
    tunnelDestroy(fixture->speed);
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseHelloStopsAfterSendAdmissionClosesLine(void)
{
    twfSetCase("SpeedTestServer Hello stops after Send admission closes the line");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);

    lineRef(fixture.line);
    g_refuse_next_line_task = true;
    g_forbid_delayed_task   = true;
    speedtestserverTunnelUpStreamPayload(fixture.speed, fixture.line, makeDownloadHello(&fixture));
    g_forbid_delayed_task = false;

    twfRequire(! lineIsAlive(fixture.line), "Send refusal did not close the borrowed server line");
    twfRequireLineStateZeroed(fixture.line, fixture.speed, "Send refusal left SpeedTestServer line state alive");
    twfRequireEqualU32(fixture.trace.prev_payload, 2, "Hello refusal did not emit exactly ACK plus Error");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "Hello refusal did not emit one downstream Finish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "Hello refusal leaked a physical line reference");
    twfRequireNoLeakedBuffers();

    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardownAfterClose(&fixture);
}

static void caseReportRejectionFinishesRealOwner(void)
{
    twfSetCase("SpeedTestServer report rejection finishes the real owner");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestserver_lstate_t *ls = lineGetState(fixture.line, fixture.speed);
    ls->report_interval_ms       = 1000;

    lineRef(fixture.line);
    g_delayed_task_submissions = 0;
    g_refuse_next_delayed_task = true;
    speedtestserverScheduleReport(fixture.speed, fixture.line, ls);

    twfRequire(! lineIsAlive(fixture.line), "report refusal left the borrowed speed-test line alive");
    twfRequireLineStateZeroed(fixture.line, fixture.speed, "report refusal retained its latch or line state");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "report refusal did not send exactly one Error frame");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "report refusal did not Finish the real owner once");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "report refusal reflected Finish away from the owner");
    twfRequireEqualU32(g_delayed_task_submissions, 1, "report refusal armed a second report");
    twfRequireNoLeakedBuffers();

    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardownAfterClose(&fixture);
}

int main(void)
{
    caseHelloStopsAfterSendAdmissionClosesLine();
    caseReportRejectionFinishesRealOwner();
    puts("speedtestserver_schedule_rejection_test: all cases passed");
    return 0;
}
