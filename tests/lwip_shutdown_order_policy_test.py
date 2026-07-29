#!/usr/bin/env python3
"""Pin the ordering barriers that make process-level lwIP teardown safe."""

import os
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
    exit_body = function_body("ww/instance/global_state.c", "exitHandle")
    require_order(
        exit_body,
        (
            "nodemanagerStop()",
            "workerRequestStop(getWorker(wid))",
            "workerJoin(getWorker(wid))",
            "workerDestroyOwnResources(getWorker(0))",
            "wwLwipShutdown()",
            "workerDestroyOwnResources(getWorker(getTotalWorkersCount() - 1))",
        ),
        "ingress and every ordinary worker must quiesce before lwIP and its pseudo-worker are destroyed",
    )

    structure = read_source("tunnels/PacketsToConnection/include/PacketsToConnection/structure.h")
    if "atomic_bool               stopping;" not in structure:
        raise AssertionError("PacketsToConnection stopping gate is not atomic")

    stop_body = function_body("tunnels/PacketsToConnection/instance/stop.c", "ptcTunnelOnStop")
    require_order(
        stop_body,
        (
            "atomicStoreRelaxed(&state->stopping, true)",
            "ptcDestroyLwipResources(t)",
        ),
        "PacketsToConnection must set its value-only stopping gate before cleanup",
    )

    payload_body = function_body(
        "tunnels/PacketsToConnection/upstream/payload.c", "ptcTunnelUpStreamPayload"
    )
    require_order(
        payload_body,
        (
            "atomicLoadRelaxed(&state->stopping)",
            "LOCK_TCPIP_CORE()",
            "atomicLoadRelaxed(&state->stopping)",
            "processV4(t, l, buf)",
        ),
        "PacketsToConnection must recheck stopping after acquiring the route-creation lock",
    )

    destroy_body = function_body(
        "tunnels/PacketsToConnection/instance/destroy.c", "ptcDestroyLwipResources"
    )
    require_order(
        destroy_body,
        (
            "LOCK_TCPIP_CORE()",
            "ptcDestroyRouteContexts(&state->route_context4)",
            "state->lwip_resources_destroyed = true",
            "UNLOCK_TCPIP_CORE()",
        ),
        "PacketsToConnection cleanup completion must be published under the core lock",
    )

    print("lwIP shutdown ordering policy passed.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print("FAIL: %s" % error, file=sys.stderr)
        sys.exit(1)
