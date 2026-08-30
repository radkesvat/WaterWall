/* Delayed junk admitted before packet-line Finish must never publish afterward. */

#include "JunkDatagramSender/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kJunkTestLargeBuffer = 8192,
    kJunkTestSmallBuffer = 1024,
};

typedef struct junk_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *junk;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *packet_line;
    line_t          *packet_lines[1];
} junk_fixture_t;

static junk_fixture_t *g_fixture;

static void fixtureSetup(junk_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, 1, kJunkTestLargeBuffer, kJunkTestSmallBuffer);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->junk = tunnelCreate(NULL, sizeof(junkdatagramsender_tstate_t), sizeof(junkdatagramsender_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->junk != NULL, "failed to create the JunkDatagramSender fixture tunnel");
    tunnelBind(fixture->prev, fixture->junk);
    tunnelBind(fixture->junk, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate the JunkDatagramSender packet chain");
    fixture->chain->workers_count        = 1;
    fixture->chain->contains_packet_node = true;
    fixture->chain->finalized            = true;
    fixture->chain->packet_lines         = fixture->packet_lines;
    fixture->junk->chain                 = fixture->chain;

    fixture->packet_line      = twfLineCreate(fixture->junk->lstate_size);
    fixture->packet_line->wid = 0;
    fixture->packet_lines[0]  = fixture->packet_line;

    junkdatagramsender_tstate_t *ts = tunnelGetState(fixture->junk);
    ts->selected_protocol_mask      = UINT64_C(1) << kJunkDatagramSenderProtocolDns;
    ts->packet_count_min            = 1;
    ts->packet_count_max            = 1;
    ts->keep_sending_max_ms         = 1;
    ts->resend_again_times          = 1;

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderLinestateInitialize(lineGetState(fixture->packet_line, fixture->junk), ts);
    discard tosSetCurrentWorker(previous_wid);
    g_fixture = fixture;
}

static void fixtureTeardown(junk_fixture_t *fixture)
{
    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelOnWorkerStop(fixture->junk, 0, wwLifecycleStartupRollback());
    junkdatagramsender_lstate_t *ls = lineGetState(fixture->packet_line, fixture->junk);
    twfRequire(ls->remaining_resend_again_times == 0 && ! ls->upstream_finished && ! ls->downstream_finished,
               "worker Stop did not zero persistent packet-line state");
    discard tosSetCurrentWorker(previous_wid);

    twfLineDestroy(fixture->packet_line);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->junk);
    tunnelDestroy(fixture->prev);
    tosWorkerEnvTeardown(&fixture->env);
    g_fixture = NULL;
}

static sbuf_t *fixturePayload(line_t *line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
    sbufSetLength(buf, 1);
    sbufGetMutablePtr(buf)[0] = UINT8_C(0xA5);
    return buf;
}

static void finishFromFirstJunk(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    junk_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && next == fixture->next, "re-entrant JunkDatagramSender callback lost its fixture");
    ++fixture->trace.next_payload;
    lineReuseBuffer(line, buf);
    junkdatagramsenderTunnelDownStreamFinish(fixture->junk, line);
}

static void caseReentrantPacketFinishStopsImmediateProgress(void)
{
    twfSetCase("JunkDatagramSender re-entrant packet Finish stops immediate progress");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture);
    fixture.next->fnPayloadU = finishFromFirstJunk;

    junkdatagramsender_tstate_t *ts = tunnelGetState(fixture.junk);
    ts->keep_sending_max_ms         = 0;

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.packet_line, fixturePayload(fixture.packet_line));

    twfRequireEqualU32(fixture.trace.next_payload, 1, "payload progress continued after re-entrant packet Finish");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "re-entrant downstream Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "re-entrant downstream Finish reflected toward its sender");
    twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 0, "re-entrant case unexpectedly armed a timer");
    twfRequire(lineIsAlive(fixture.packet_line), "re-entrant Finish destroyed the packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void casePacketFinishSuppressesDelayedJunk(void)
{
    twfSetCase("JunkDatagramSender packet Finish suppresses delayed junk");
    tosResetProcessApi(true);

    junk_fixture_t fixture;
    fixtureSetup(&fixture);

    const wid_t previous_wid = tosSetCurrentWorker(0);
    junkdatagramsenderTunnelUpStreamPayload(fixture.junk, fixture.packet_line, fixturePayload(fixture.packet_line));

    twfRequireEqualU32(
        fixture.trace.next_payload, 2, "the immediate junk and original packet were not both published before Finish");
    twfRequireEqualU32(
        (uint32_t) fixture.env.loops[0]->ntimers, 1, "the delayed junk copy did not arm its owner-worker timer");
    twfRequire(twfLineRefCount(fixture.packet_line) > 1, "the delayed junk copy did not retain the packet line");

    junkdatagramsenderTunnelDownStreamFinish(fixture.junk, fixture.packet_line);
    junkdatagramsender_lstate_t *ls = lineGetState(fixture.packet_line, fixture.junk);
    twfRequire(ls->upstream_finished && ls->downstream_finished,
               "packet Finish did not terminalize both delayed publication directions");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "downstream packet Finish did not propagate toward prev");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "downstream packet Finish reflected toward next");
    twfRequire(lineIsAlive(fixture.packet_line), "JunkDatagramSender destroyed the chain-owned packet line");

    wwSleepMS(20);
    tosPumpWorker(&fixture.env, 0);

    twfRequireEqualU32(fixture.trace.next_payload, 2, "delayed junk was published after packet-line Finish");
    twfRequire(lineIsAlive(fixture.packet_line), "delayed settlement destroyed the packet line");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();

    caseReentrantPacketFinishStopsImmediateProgress();
    casePacketFinishSuppressesDelayedJunk();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("junkdatagramsender_packet_lifecycle_test: all cases passed");
    return 0;
}
