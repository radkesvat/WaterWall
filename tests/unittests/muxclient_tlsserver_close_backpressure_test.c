#include "mux_tls_close_backpressure_fixture.h"

static void runMuxClientTlsServerCase(mxb_terminal_cause_t cause)
{
    mxb_fixture_t fixture;
    memoryZero(&fixture, sizeof(fixture));

    mxbTlsServerCreate(&fixture);
    mxbMuxClientCreate(&fixture);
    tunnelBind(fixture.tls, fixture.mux);

    fixture.tls->lstate_offset          = 0;
    fixture.mux->lstate_offset          = fixture.tls->lstate_size;
    const uint32_t combined_lstate_size = fixture.tls->lstate_size + fixture.mux->lstate_size;
    mxbSetupEnvironment(&fixture, combined_lstate_size);

    fixture.parent = mxbCreateLine(&fixture);
    fixture.child  = mxbCreateLine(&fixture);
    lineRef(fixture.child);
    mxbMuxClientInitializeLines(&fixture);
    mxbTlsServerInitializeLine(&fixture);

    mxbTlsServerPauseWire(&fixture);
    mxbRequire(mxbMuxClientChildIsPaused(&fixture),
               "real TlsServer wire Pause did not synchronously pause the MuxClient child");

    mxbMuxClientFeedParent(&fixture, cause == kMxbTerminalPeerClose);
    if (cause == kMxbTerminalParentLoss)
    {
        lineRef(fixture.parent);
        mxbMuxClientFinishParent(&fixture);
        mxbRequire(! lineIsAlive(fixture.parent), "MuxClient parent loss left its owned parent alive");
        mxbRequire(mxbLineStateIsZero(fixture.parent, fixture.mux), "MuxClient parent loss retained parent line state");
        lineUnref(fixture.parent);
        fixture.parent = NULL;
    }

    mxbRequire(lineIsAlive(fixture.child), "MuxClient completed the child while the TLS wire was paused");
    mxbRequire(mxbMuxClientChildQueuedBytes(&fixture) == kMxbPlaintextLength,
               "MuxClient did not retain every paused child byte");
    mxbRequire(fixture.tls_plaintext_calls == 0 && fixture.tls_plaintext_bytes == 0,
               "MuxClient sent retained plaintext into TlsServer before wire Resume");
    mxbRequire(mxbTlsServerShapedBytes(&fixture) == 0 && fixture.wire_payload_calls == 0,
               "retained MuxClient bytes grew TlsServer shaped output before Resume");
    mxbRequire(fixture.child_owner_finish_calls == 0 && lineIsAlive(fixture.child),
               "MuxClient/TlsServer sent Finish before the empty-and-unpaused barrier");

    if (cause == kMxbTerminalPeerClose)
    {
        mxbRequire(mxbMuxClientChildIsPeerDraining(&fixture),
                   "MuxClient peer Close did not publish PeerDraining before TLS callbacks");
        mxbRequire(mxbMuxClientParentQueuedBytes(&fixture) == kMxbPlaintextLength,
                   "MuxClient peer Close lost parent queued-byte accounting");
    }
    else
    {
        mxbRequire(mxbMuxClientChildIsParentGoneDraining(&fixture) && mxbMuxClientChildHasNoParent(&fixture),
                   "MuxClient parent loss did not publish a pointer-free detached drain");
        mxbRequire(mxbMuxClientDetachedChildren(&fixture) == 1 &&
                       mxbMuxClientDetachedBytes(&fixture) == kMxbPlaintextLength,
                   "MuxClient parent loss published incorrect detached accounting");
    }

    mxbTlsServerResumeWire(&fixture);

    mxbRequire(lineIsAlive(fixture.child), "MuxClient/TlsServer drained all pressure in the first Resume unexpectedly");
    mxbRequire(fixture.tls_plaintext_calls > 0 && fixture.tls_plaintext_calls < fixture.expected_mux_data_frames,
               "nested TLS shaping Pause did not stop MuxClient between queued Data frames");
    mxbRequire(mxbTlsServerProducerPaused(&fixture) && mxbMuxClientChildIsPaused(&fixture),
               "TlsServer high-water Pause was not retained by MuxClient");
    mxbRequire(mxbMuxClientChildQueuedBytes(&fixture) > 0, "MuxClient popped a second tranche after nested TLS Pause");
    mxbRequire(fixture.wire_payload_calls == 0,
               "delayed TlsServer shaping output reached the peer before explicit ready-output driving");

    for (uint32_t attempt = 0; attempt < kMxbMaximumDriveAttempts && lineIsAlive(fixture.child); ++attempt)
    {
        discard mxbTlsServerForceReadyOutput(&fixture);
    }

    mxbRequire(! lineIsAlive(fixture.child), "MuxClient/TlsServer did not complete after deterministic output drains");
    mxbRequire(fixture.tls_plaintext_calls == fixture.expected_mux_data_frames &&
                   fixture.tls_plaintext_bytes == kMxbPlaintextLength,
               "MuxClient/TlsServer did not accept every MUX Data frame exactly once");
    mxbRequire(fixture.child_owner_finish_calls == 1 && fixture.child_owner_destroyed && fixture.wire_finish_calls == 1,
               "the true MuxClient child owner did not finish and destroy exactly once");
    mxbRequire(fixture.decrypted_at_finish == kMxbPlaintextLength,
               "TlsServer Finish reached the child owner before all plaintext was decrypted");
    mxbRequire(mxbLineStateIsZero(fixture.child, fixture.mux) && mxbLineStateIsZero(fixture.child, fixture.tls),
               "MuxClient/TlsServer child state survived terminal completion");
    mxbRequire((uint32_t) atomicLoadRelaxed(&fixture.child->refc) == 1,
               "MuxClient borrowed-child completion changed the outer reference count incorrectly");
    if (cause == kMxbTerminalPeerClose)
    {
        mxbRequire(mxbMuxClientParentQueuedBytes(&fixture) == 0,
                   "MuxClient peer-close completion retained parent queued bytes");
    }
    else
    {
        mxbRequire(mxbMuxClientDetachedChildren(&fixture) == 0 && mxbMuxClientDetachedBytes(&fixture) == 0,
                   "MuxClient detached accounting survived terminal completion");
    }
    mxbRequirePlaintext(&fixture);

    lineUnref(fixture.child);
    fixture.child = NULL;
    mxbMuxClientDestroy(&fixture);
    mxbTlsServerDestroy(&fixture);
    mxbTeardownEnvironment(&fixture);
}

int main(void)
{
    mxbRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    mxbRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();
    mxbRequire(wCryptoGlobalInit() == kWCryptoOk, "OpenSSL global initialization failed");
    runMuxClientTlsServerCase(kMxbTerminalPeerClose);
    runMuxClientTlsServerCase(kMxbTerminalParentLoss);
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    printf("muxclient_tlsserver_close_backpressure_test: all cases passed\n");
    return 0;
}
