#!/usr/bin/env python3
"""Pin the ordering barriers that make process-level lwIP teardown safe."""

import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tunnels_abort_policy_test import ROOT, analyze, resolve_function  # noqa: E402


def read_source(rel_path):
    with open(os.path.join(ROOT, rel_path), "r", encoding="utf-8") as handle:
        return handle.read()


def function_body(rel_path, function):
    content = read_source(rel_path)
    errors = []
    span = resolve_function(content, rel_path, function, "lwIP shutdown", errors)
    if span is None:
        raise AssertionError("\n".join(errors))
    return analyze(content)[0][span[0]:span[1]]


def require_order(body, tokens, description):
    cursor = 0
    for token in tokens:
        position = body.find(token, cursor)
        if position < 0:
            raise AssertionError("%s: missing or out-of-order token %r" % (description, token))
        cursor = position + len(token)


def main():
    exit_body = function_body("ww/instance/global_state.c", "globalstateRunShutdownSequence")
    require_order(
        exit_body,
        (
            "nodemanagerQuiesceRequest(&context)",
            "workerRequestQuiesceWithContext(worker, &context)",
            "workerPerformQuiesce(getWorker(0), &context)",
            "globalstateRequireWorkerPhase(kWorkerLifecycleQuiesced)",
            "nodemanagerQuiesceWait(&context)",
            "workerRequestDrain(worker)",
            "workerPerformDrain(getWorker(0), &context)",
            "globalstateRequireWorkerPhase(kWorkerLifecycleDrained)",
            "nodemanagerStop(&context)",
            "workerRequestTeardown(worker)",
            "workerPerformTeardown(getWorker(0))",
            "globalstateRequireWorkerPhase(kWorkerLifecycleExited)",
            "workerJoin(worker)",
            "wwLwipShutdown()",
        ),
        "the controller must join all owners before shared lwIP finalization",
    )

    structure = read_source("tunnels/PacketsToConnection/include/PacketsToConnection/structure.h")
    if re.search(r"\batomic_bool\s+stopping\s*;", structure) is None:
        raise AssertionError("PacketsToConnection stopping gate is not atomic")

    quiesce_body = function_body(
        "tunnels/PacketsToConnection/instance/pre_stop.c", "ptcTunnelOnQuiesceRequest"
    )
    if "atomicStoreRelaxed(&state->stopping, true)" not in quiesce_body:
        raise AssertionError("PacketsToConnection does not close its stopping gate during quiesce")

    worker_quiesce = function_body("ww/instance/worker.c", "workerPerformQuiesce")
    require_order(worker_quiesce,
                  ("wwLwipRuntimeQuiesceWorker(worker->wid)", "wloopQuiesceNormalWork(worker->loop)"),
                  "engine timers must detach before normal work is discarded")
    worker_teardown = function_body("ww/instance/worker.c", "workerPerformTeardown")
    require_order(worker_teardown,
                  ("workerMessagesCloseAdmissionAndDetach", "workerMessagesDestroyDetached(queue)",
                   "wwLwipRuntimeDestroyWorker(worker->wid)", "wloopDestroy(&loop)", "workerDestroyPools(worker)"),
                  "engine release requires settled messages and live saved loop/pools")
    shared = function_body("ww/lwip/ww_lwip.c", "wwLwipShutdown")
    require_order(shared, ("wwLwipRuntimeFinalize()", "wwLwipEraseProtocolState()"),
                  "ISN secret must outlive every engine")

    payload_body = function_body("tunnels/PacketsToConnection/upstream/payload.c", "ptcTunnelUpStreamPayload")
    require_order(payload_body,
                  ("atomicLoadRelaxed(&state->stopping)", "wwLwipRuntimeGet(lineGetWID(l))",
                   "wwLwipEngineEnter(engine, &previous)", "atomicLoadRelaxed(&state->stopping)",
                   "processV4(t, l, buf)"),
                  "PTC admission requires its delivered packet owner's engine")
    ptc_stop = function_body("tunnels/PacketsToConnection/instance/stop.c", "ptcTunnelOnWorkerStop")
    require_order(ptc_stop, ("ptcDrainOwnedLinesOnCurrentWorker(t, wid)", "ptcDestroyWorkerRoute(t, wid)"),
                  "PTC must finish owned lines before removing their route")
    ctp_stop = function_body("tunnels/ConnectionToPackets/instance/stop.c", "ctpTunnelOnWorkerStop")
    require_order(ctp_stop, ("ctpDrainTerminalLinesOnCurrentWorker(t, wid)", "ctpDetachWorkerLines(t, wid)",
                            "ctpDestroyWorkerNetif(t, wid)"),
                  "CTP must detach borrowed-line PCBs before removing their netif")

    print("lwIP shutdown ordering policy passed.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        sys.exit(1)
