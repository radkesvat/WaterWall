#include "mux_tls_close_backpressure_fixture.h"

static void runMuxServerTlsClientCase(mxb_terminal_cause_t cause)
{
    mxb_fixture_t fixture;
    memoryZero(&fixture, sizeof(fixture));

    mxbMuxServerCreate(&fixture);
    mxbTlsClientCreate(&fixture);
    tunnelBind(fixture.mux, fixture.tls);

    fixture.mux->lstate_offset          = 0;
    fixture.tls->lstate_offset          = fixture.mux->lstate_size;
    const uint32_t combined_lstate_size = fixture.mux->lstate_size + fixture.tls->lstate_size;
    mxbSetupEnvironment(&fixture, combined_lstate_size);

    fixture.parent = mxbCreateLine(&fixture);
    fixture.child  = mxbCreateLine(&fixture);
    lineRef(fixture.child);
    mxbMuxServerInitializeLines(&fixture);
    mxbTlsClientInitializeLine(&fixture);

    mxbTlsClientPauseWire(&fixture);
    mxbRequire(mxbMuxServerChildIsPaused(&fixture),
               "real TlsClient wire Pause did not synchronously pause the MuxServer child");

    mxbMuxServerFeedParent(&fixture, cause == kMxbTerminalPeerClose);
    if (cause == kMxbTerminalParentLoss)
    {
        mxbMuxServerFinishParent(&fixture);
        mxbRequire(lineIsAlive(fixture.parent), "MuxServer destroyed its borrowed parent on parent loss");
        mxbRequire(mxbLineStateIsZero(fixture.parent, fixture.mux),
                   "MuxServer parent loss retained borrowed parent state");
    }

    mxbRequire(lineIsAlive(fixture.child), "MuxServer completed its owned child while the TLS wire was paused");
    mxbRequire(mxbMuxServerChildQueuedBytes(&fixture) == kMxbPlaintextLength,
               "MuxServer did not retain every paused child byte");
    const size_t retained_charge = mxbMuxServerChildQueueCharge(&fixture);
    mxbRequire(retained_charge > kMxbPlaintextLength,
               "MuxServer retained payload without charging its backing allocations");
    mxbRequire(fixture.tls_plaintext_calls == 0 && fixture.tls_plaintext_bytes == 0,
               "MuxServer sent retained plaintext into TlsClient before wire Resume");
    mxbRequire(mxbTlsClientShapedBytes(&fixture) == 0 && fixture.wire_payload_calls == 0,
               "retained MuxServer bytes grew TlsClient shaped output before Resume");
    mxbRequire(fixture.wire_finish_calls == 0 && lineIsAlive(fixture.child),
               "MuxServer/TlsClient sent Finish before the empty-and-unpaused barrier");

    if (cause == kMxbTerminalPeerClose)
    {
        mxbRequire(mxbMuxServerChildIsPeerDraining(&fixture),
                   "MuxServer peer Close did not publish PeerDraining before TLS callbacks");
        mxbRequire(mxbMuxServerParentQueueCharge(&fixture) == retained_charge,
                   "MuxServer peer Close lost exact parent queue-charge accounting");
    }
    else
    {
        mxbRequire(mxbMuxServerChildIsParentGoneDraining(&fixture) && mxbMuxServerChildHasNoParent(&fixture),
                   "MuxServer parent loss did not publish a pointer-free detached drain");
        mxbRequire(mxbMuxServerDetachedChildren(&fixture) == 1 &&
                       mxbMuxServerDetachedCharge(&fixture) == retained_charge &&
                       mxbMuxServerDetachedHeadIsChild(&fixture),
                   "MuxServer parent loss published incorrect owner-registry accounting");
    }

    mxbTlsClientResumeWire(&fixture);

    mxbRequire(lineIsAlive(fixture.child), "MuxServer/TlsClient drained all pressure in the first Resume unexpectedly");
    mxbRequire(fixture.tls_plaintext_calls > 0 && fixture.tls_plaintext_calls < fixture.expected_mux_data_frames,
               "nested TLS shaping Pause did not stop MuxServer between queued Data frames");
    mxbRequire(mxbTlsClientProducerPaused(&fixture) && mxbMuxServerChildIsPaused(&fixture),
               "TlsClient high-water Pause was not retained by MuxServer");
    mxbRequire(mxbMuxServerChildQueuedBytes(&fixture) > 0, "MuxServer popped a second tranche after nested TLS Pause");
    if (cause == kMxbTerminalPeerClose)
    {
        mxbRequire(mxbMuxServerParentQueueCharge(&fixture) == mxbMuxServerChildQueueCharge(&fixture),
                   "MuxServer attached partial drain unbalanced child and parent charge");
    }
    else
    {
        mxbRequire(mxbMuxServerDetachedCharge(&fixture) == mxbMuxServerChildQueueCharge(&fixture),
                   "MuxServer detached partial drain unbalanced child and registry charge");
    }
    mxbRequire(fixture.wire_payload_calls == 0,
               "delayed TlsClient shaping output reached the peer before explicit ready-output driving");

    for (uint32_t attempt = 0; attempt < kMxbMaximumDriveAttempts && lineIsAlive(fixture.child); ++attempt)
    {
        discard mxbTlsClientForceReadyOutput(&fixture);
    }

    mxbRequire(! lineIsAlive(fixture.child), "MuxServer/TlsClient did not complete after deterministic output drains");
    mxbRequire(fixture.tls_plaintext_calls == fixture.expected_mux_data_frames &&
                   fixture.tls_plaintext_bytes == kMxbPlaintextLength,
               "MuxServer/TlsClient did not accept every MUX Data frame exactly once");
    mxbRequire(fixture.wire_finish_calls == 1,
               "TlsClient did not finish its wire side exactly once before owned-child destruction");
    mxbRequire(fixture.decrypted_at_finish == kMxbPlaintextLength,
               "TlsClient Finish reached the wire before all plaintext was decrypted");
    mxbRequire(mxbLineStateIsZero(fixture.child, fixture.mux) && mxbLineStateIsZero(fixture.child, fixture.tls),
               "MuxServer/TlsClient child state survived terminal completion");
    mxbRequire((uint32_t) atomicLoadRelaxed(&fixture.child->refc) == 1,
               "MuxServer did not destroy its owned child exactly once");
    if (cause == kMxbTerminalPeerClose)
    {
        mxbRequire(mxbMuxServerParentQueueCharge(&fixture) == 0,
                   "MuxServer peer-close completion retained parent queue charge");
    }
    else
    {
        mxbRequire(mxbMuxServerDetachedChildren(&fixture) == 0 && mxbMuxServerDetachedCharge(&fixture) == 0,
                   "MuxServer detached registry survived terminal completion");
    }
    mxbRequirePlaintext(&fixture);

    lineUnref(fixture.child);
    fixture.child = NULL;
    mxbMuxServerDestroy(&fixture);
    mxbTlsClientDestroy(&fixture);
    mxbTeardownEnvironment(&fixture);
}

int main(void)
{
    mxbRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    mxbRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    runMuxServerTlsClientCase(kMxbTerminalPeerClose);
    runMuxServerTlsClientCase(kMxbTerminalParentLoss);
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    printf("muxserver_tlsclient_close_backpressure_test: all cases passed\n");
    return 0;
}
