/*
 * Covers: decoded TCP/UDP worker ownership, checksum requests and packet lifetime.
 * Setup: real worker queues, packet-line identities and shared fragment table.
 * Cases: cross/same/single-worker delivery; opaque and normal-line pass-through;
 * admission refusal, foreign cancellation, dead target, late fragments and shutdown.
 * Limits: kernel queue selection and decoder wire formats have separate coverage.
 * CTest: waterwall.packet_affinity_unit
 */
#include "devices/device_flow_affinity.h"
#include "devices/device_packet_checksum_internal.h"
#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "packet_affinity.h"

typedef struct affinity_fixture_s
{
    tos_worker_env_t   env;
    tunnel_t          *tunnel;
    tunnel_chain_t    *chain;
    line_t            *lines[kTosMaxWorkers];
    packet_affinity_t *affinity;
    unsigned           delivered;
    wid_t              last_wid;
    bool               requested;
    uint16_t           fragments[8];
} affinity_fixture_t;

static void receivePacket(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    affinity_fixture_t *fixture = *(affinity_fixture_t **) tunnelGetState(t);
    twfRequire(lineIsOnCurrentWorker(line), "decoded packet ran on another line's worker");
    twfRequire(fixture->delivered < 8, "too many decoded packets");
    fixture->fragments[fixture->delivered++] = GET_BE16((const uint8_t *) sbufGetRawPtr(buf) + 6);
    fixture->last_wid                        = lineGetWID(line);
    fixture->requested                       = packettunnelTakeChecksumRequest(line);
    lineReuseBuffer(line, buf);
}

static void setup(affinity_fixture_t *fixture, wid_t workers)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, workers, 8192, 2048);
    fixture->tunnel = tunnelCreate(NULL, sizeof(affinity_fixture_t *), 0);
    twfRequire(fixture->tunnel != NULL, "could not create decoder fixture");
    *(affinity_fixture_t **) tunnelGetState(fixture->tunnel) = fixture;
    fixture->chain                                           = tunnelchainCreate(workers);
    fixture->chain->packet_lines                             = fixture->lines;
    fixture->tunnel->chain                                   = fixture->chain;
    for (wid_t wid = 0; wid < workers; ++wid)
    {
        fixture->lines[wid]      = twfLineCreate(0);
        fixture->lines[wid]->wid = wid;
    }
    fixture->affinity = packetAffinityCreate(fixture->tunnel, receivePacket);
    twfRequire(fixture->affinity != NULL, "could not create packet affinity");
}

static void teardown(affinity_fixture_t *fixture)
{
    packetAffinityDestroy(fixture->affinity);
    for (wid_t wid = 0; wid < fixture->env.count; ++wid)
    {
        twfRequire(twfLineRefCount(fixture->lines[wid]) == 1, "queued packet retained its target line");
        twfLineDestroy(fixture->lines[wid]);
    }
    twfRequire(g_twf_buffers.live_count == 0, "decoded packet was neither delivered nor discarded");
    tunnelDestroy(fixture->tunnel);
    memoryFree(fixture->chain);
    tosWorkerEnvTeardown(&fixture->env);
}

static sbuf_t *makePacket(uint8_t protocol, wid_t target, bool fragmented, bool tail)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
    sbufSetLength(buf, 36);
    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, 36);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = protocol;
    PUT_BE16(packet + 2, 36);
    PUT_BE16(packet + 4, 123);
    PUT_BE32(packet + 12, UINT32_C(0xC0000201));
    PUT_BE32(packet + 16, UINT32_C(0xC6336401));
    PUT_BE16(packet + 22, 443);
    for (uint32_t port = 1000;; ++port)
    {
        twfRequire(port <= UINT16_MAX, "could not find desired test worker");
        PUT_BE16(packet + 20, (uint16_t) port);
        wid_t wid;
        twfRequire(deviceFlowAffineWID(packet, 36, &wid), "test packet was not hashable");
        if (wid == target || (protocol != 6 && protocol != 17))
            break;
    }
    if (fragmented)
        PUT_BE16(packet + 6, tail ? 2 : 0x2000);
    PUT_BE16(packet + 10, deviceIpv4HeaderChecksum(packet, 20));
    return buf;
}

static void caseWorkerSelection(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    for (uint8_t protocol = 6; protocol <= 17; protocol += 11)
    {
        lineSetRecalculateChecksum(fixture.lines[0], true);
        packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(protocol, 2, false, false));
        twfRequire(! lineGetRecalculateChecksum(fixture.lines[0]), "handoff left checksum request on source");
        const unsigned before = fixture.delivered;
        tosPumpWorker(&fixture.env, 2);
        twfRequire(fixture.delivered == before + 1 && fixture.last_wid == 2 && fixture.requested,
                   "decoded TCP/UDP packet or checksum request reached the wrong worker");
    }
    const unsigned before = fixture.delivered;
    packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(17, 0, false, false));
    twfRequire(fixture.delivered == before + 1 && fixture.last_wid == 0, "same-worker delivery was queued");
    packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(50, 0, false, false));
    twfRequire(fixture.delivered == before + 2 && fixture.last_wid == 0, "opaque input was redistributed");
    line_t *normal = twfLineCreate(0);
    packetAffinityForward(fixture.affinity, normal, makePacket(17, 3, false, false));
    twfRequire(fixture.delivered == before + 3 && fixture.last_wid == 0, "normal line escaped its owner");
    twfLineDestroy(normal);
    teardown(&fixture);
}

static void caseFragmentFlow(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(17, 2, true, true));
    twfRequire(fixture.delivered == 0 && g_twf_buffers.live_count == 1, "tail was not staged pending ports");
    testWorkerBindWID(1);
    packetAffinityForward(fixture.affinity, fixture.lines[1], makePacket(17, 2, true, false));
    twfRequire(fixture.delivered == 0, "fragments ran on a reader instead of the flow owner");
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 2 && fixture.last_wid == 2 && fixture.fragments[0] == 2 &&
                   fixture.fragments[1] == 0x2000,
               "fragment handoff changed affinity, boundaries or release order");
    packetAffinityForward(fixture.affinity, fixture.lines[1], makePacket(17, 2, false, false));
    tosPumpWorker(&fixture.env, 2);
    twfRequire(fixture.delivered == 3 && fixture.last_wid == 2, "complete flow and fragments split workers");
    packetAffinityForward(fixture.affinity, fixture.lines[1], makePacket(17, 2, true, true));
    teardown(&fixture); /* Destroy must release the new incomplete datagram. */
}

static void caseSettlement(unsigned mode)
{
    affinity_fixture_t fixture;
    setup(&fixture, 4);
    if (mode == 0)
        workerMessagesCloseAdmission(&fixture.env.workers[2]);
    packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(6, 2, false, false));
    if (mode == 1)
    {
        /* Admission closes before execution; cleanup runs on a foreign thread
         * identity and must not invoke the decoder or borrow either pool. */
        workerMessagesCloseAdmission(&fixture.env.workers[2]);
        testWorkerUnbindWID();
        workerMessagesCleanupPending(&fixture.env.workers[2]);
        testWorkerBindWID(0);
    }
    else if (mode == 2)
    {
        fixture.lines[2]->alive = false;
        tosPumpWorker(&fixture.env, 2);
    }
    twfRequire(fixture.delivered == 0, "refused/canceled/dead-target packet reached a continuation");
    teardown(&fixture);
}

static void caseSingleWorker(void)
{
    affinity_fixture_t fixture;
    setup(&fixture, 1);
    lineSetRecalculateChecksum(fixture.lines[0], true);
    packetAffinityForward(fixture.affinity, fixture.lines[0], makePacket(6, 0, false, false));
    twfRequire(fixture.delivered == 1 && fixture.requested, "single-worker fast path changed checksum metadata");
    teardown(&fixture);
}

int main(void)
{
    testCaseSet("packet affinity worker selection");
    caseWorkerSelection();
    testCaseSet("packet affinity fragments");
    caseFragmentFlow();
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        testCaseSet("packet affinity settlement");
        caseSettlement(mode);
    }
    testCaseSet("packet affinity one worker");
    caseSingleWorker();
    return 0;
}
