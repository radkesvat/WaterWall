#!/usr/bin/env python3
"""Category-B orderly-shutdown source policy checker.

Category D (tests/tunnels_abort_policy_test.py) pins the failures that must kill
the process immediately. This checker pins the opposite policy: a runtime
failure that leaves the process structurally valid but unable to continue
correctly must

    release caller-owned buffers, handles and locks;
    call requestProgramShutdown(1);
    fall back to abortProgramNow(1) only if the worker-0 handoff was refused;
    return through the current callback without doing any further work.

Every site is identified by (relative source path, exact function name) and
never by a line number. Function bodies are extracted with the lexical C scanner
from tunnels_abort_policy_test.py, which blanks comments, string literals and
character literals before any call is counted, so a commented-out or quoted
lookalike can never satisfy a candidate.

Usage:
    python3 tests/tunnels_orderly_shutdown_policy_test.py [--mutation-test|-m]
"""
import os
import re
import sys

# Importing the sibling checker must not leave a __pycache__ directory behind in
# the source tree when this runs from a build directory.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tunnels_abort_policy_test import (  # noqa: E402
    ROOT,
    analyze,
    count_calls,
    line_of,
    resolve_function,
)

# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------
#
# Category-B implementations. Each entry is:
#
#   (relative path,
#    exact function name,
#    tuple of expected exit-code expressions, in source order, one per
#      request/fallback site,
#    tuple of anchors that must appear before the first request, in order,
#    short classification description)
#
# The anchors are the stable diagnostic and cleanup work that must happen while
# this callback still owns it: the request may only come afterwards.

CATEGORY_B = [
    # ------------------------------------------------------------------
    # Converted by the orderly-runtime-failure audit.
    # ------------------------------------------------------------------
    ("tunnels/AuthenticationClient/instance/start.c", "authenticationclientStartPingTimer",
     ("1",),
     ("AuthenticationClient: failed to create ping timer",),
     "worker-0 startup task: required ping timer could not be created"),
    ("tunnels/AuthenticationClient/common/protocol.c", "authenticationclientStartSyncTimer",
     ("1",),
     ("AuthenticationClient: failed to create sync timer",),
     "worker-0 startup task: required sync timer could not be created"),
    ("tunnels/AuthenticationClient/common/protocol.c", "authenticationclientScheduleReconnect",
     ("1",),
     ("mutexUnlock(&ts->control_mutex);",
      "AuthenticationClient: failed to create reconnect timer"),
     "worker-0 runtime task: required reconnect timer could not be created"),
    ("tunnels/KeepAliveClient/instance/start.c", "keepaliveclientStartWorkerTimer",
     ("1",),
     ("KeepAliveClient: failed to create periodic keepalive timer on worker %u",),
     "per-worker task: required periodic timer could not be created"),
    ("tunnels/PacketsToStream/instance/start.c", "packetstostreamStartWorkerTimer",
     ("1",),
     ("PacketsToStream: failed to create sensitive-mode timer on worker %u",),
     "per-worker task: required heartbeat timer could not be created"),
    ("tunnels/PacketsToStream/common/helpers.c", "packetstostreamSendSensitivePing",
     ("1",),
     ("packetstostreamArmTimeoutTimer(t, lineGetWID(packet_line))",
      "lineReuseBuffer(packet_line, buf);"),
     "sensitive-mode ping: the heartbeat is recycled before the request"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderReportInitialTimerFailure",
     ("1",),
     ("PacketSender: failed to create worker timer on worker %u",),
     "per-worker task: initial deadline timer could not be created"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderReportTimerRearmFailure",
     ("1",),
     ("PacketSender: failed to rearm worker timer on worker %u",),
     "per-worker task: an existing deadline timer could not be rearmed"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientFail",
     ("1",),
     ("TesterClient: worker %u failed: %s",),
     "test driver: the single TesterClient runtime-verdict helper"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverFail",
     ("1",),
     ("TesterServer: worker %u failed: %s",),
     "test driver: the single TesterServer runtime-verdict helper"),
    # ------------------------------------------------------------------
    # Pre-existing implementations this policy was derived from. They are
    # covered here so the reference pattern cannot regress either.
    # ------------------------------------------------------------------
    ("ww/devices/tun/tun_linux.c", "tundeviceNoteUnexpectedThreadExit",
     ("1",),
     ("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable",),
     "reference: published Linux TUN device I/O thread failure"),
    ("ww/devices/tun/tun_darwin.c", "tundeviceNoteUnexpectedThreadExit",
     ("1",),
     ("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable",),
     "reference: published Darwin TUN device I/O thread failure"),
    ("ww/devices/tun/tun_windows.c", "tundeviceNoteUnexpectedThreadExit",
     ("1",),
     ("TunDevice: %s thread for device %s exited unexpectedly; the device is no longer usable",),
     "reference: published Windows TUN device I/O thread failure"),
    ("tunnels/PacketReceiver/common/helpers.c", "packetreceiverFinalizeReport",
     ("1", "0"),
     ("mutexUnlock(&state->state_mutex);",
      "PacketReceiver: failed to write report to"),
     "reference: runtime report-write failure, then Category-A completion"),
    ("tunnels/SpeedTestClient/common/helpers.c", "speedtestclientFinishLine",
     ("final_success ? 0 : 1",),
     ("lineUnlock(l);",),
     "reference: final speed-test result, success or failure"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientRequestSuccessfulShutdown",
     ("0",),
     ("TesterClient: all %u worker lines completed successfully",),
     "reference: Category-A completion isolated from every invariant abort"),
]


# Callers that must stop as soon as a helper reports "shutdown requested".
# Each entry lists source snippets that must appear in the body in this exact
# relative order; the guard's own `return;` is one of them, so deleting it
# breaks the sequence.
#
#   (relative path, function, ordered snippets, description)

CALLER_STOPS = [
    ("tunnels/AuthenticationClient/instance/start.c", "authenticationclientStartOnWorker0",
     ("if (! authenticationclientStartPingTimer(worker, t, ts))",
      "return;",
      "if (! authenticationclientStartSyncTimer(t))",
      "return;",
      "authenticationclientOpenControlLine(t);"),
     "a failed ping or sync timer must stop before the control line is opened"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderSendReadyPackets",
     ("if (packetsenderWaitUntilDeadline(slot, current_deadline_ms) != kPacketSenderDeadlineReady)",
      "return;",
      "packetsenderResolvePacketView(",
      "slot->next_packet_index = current_index + 1U;"),
     "only a reached deadline may resolve a packet view or advance the index"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderWaitUntilDeadline",
     ("if (! packetsenderArmWorkerTimer(slot, (remaining_ms == 0U) ? 1U : remaining_ms))",
      "return kPacketSenderDeadlineShutdownRequested;"),
     "a timer failure must never be reported as a reached deadline"),
    ("tunnels/PacketsToStream/common/helpers.c", "packetstostreamSendSensitivePing",
     ("if (! packetstostreamArmTimeoutTimer(t, lineGetWID(packet_line)))",
      "lineReuseBuffer(packet_line, buf);",
      "return false;",
      "ls->awaiting_pong"),
     "the pong state is only published after the timeout timer is armed"),
]


# Category-D branches inside the tester tunnels. Each diagnostic must be
# followed by a hard abort and must never reach the orderly verdict helper.
#
#   (relative path, function, diagnostic anchor, description)

TESTER_INVARIANTS = [
    ("tunnels/TesterClient/common/helpers.c", "testerclientCreatePayload",
     "TesterClient: packet-mode payload generation attempted to split a packet chunk",
     "impossible payload-generator state"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCreatePayload",
     "TesterClient: packet-mode requires enough small-buffer capacity for the maximum packet length",
     "impossible payload-generator state"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCreatePayload",
     "TesterClient: stream-mode payload generation exceeded large buffer size",
     "impossible payload-generator state"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCreatePayload",
     "TesterClient: packet-ipv4 chunk size is smaller than the configured packet headers",
     "impossible payload-generator state"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientRequestSendTask",
     "TesterClient: large buffer pool reports zero writable payload capacity",
     "zero writable large-buffer capacity"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCloseCompletedStreamTask",
     "TesterClient: scheduled close before response verification completed",
     "close scheduled before verification"),
    ("tunnels/TesterClient/downstream/payload.c", "testerclientTunnelDownStreamPayloadStateless",
     "TesterClient: packet-mode stateless response count reached completion with missing chunks",
     "stateless response count/mask disagreement"),
    ("tunnels/TesterClient/downstream/fin.c", "testerclientTunnelDownStreamFinish",
     "TesterClient: packet-mode received unexpected finish on worker packet line",
     "Finish on a persistent worker packet line"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverCreatePayload",
     "TesterServer: packet-mode payload generation attempted to split a packet chunk",
     "impossible payload-generator state"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverCreatePayload",
     "TesterServer: packet-mode response exceeded small buffer size",
     "impossible payload-generator state"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverCreatePayload",
     "TesterServer: stream-mode payload generation exceeded large buffer size",
     "impossible payload-generator state"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverCreatePayload",
     "TesterServer: packet-ipv4 chunk size is smaller than the configured packet headers",
     "impossible payload-generator state"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverResponseSendTask",
     "TesterServer: large buffer pool reports zero writable payload capacity",
     "zero writable large-buffer capacity"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverResponseSendTask",
     "TesterServer: packet line died during packet-mode response send",
     "persistent packet line died"),
    ("tunnels/TesterServer/upstream/fin.c", "testerserverTunnelUpStreamFinish",
     "TesterServer: packet-mode received unexpected finish on worker packet line",
     "Finish on a persistent worker packet line"),
    ("tunnels/TesterServer/downstream/fin.c", "testerserverTunnelDownStreamFinish",
     "TesterServer: packet-mode received unexpected downstream finish on worker packet line",
     "Finish on a persistent worker packet line"),
    ("tunnels/TesterServer/downstream/fin.c", "testerserverTunnelDownStreamFinish",
     "TesterServer: downStreamFinish disabled",
     "disabled stream-mode downstream-finish callback"),
    ("ww/managers/node_manager.c", "nodemanagerInitializeLineOnTargetWorker",
     "NodeManager: node startup failure: line initialization failed for node",
     "persistent packet line died during chain initialization"),
]


# Verdict sites whose incoming buffer is still owned by the callback. The
# recycle must appear before the verdict call.
#
#   (relative path, function, exact verdict call prefix, recycle snippet, why)

RECYCLE_BEFORE_VERDICT = [
    ("tunnels/TesterClient/downstream/payload.c", "testerclientTunnelDownStreamPayloadStateless",
     'testerclientFail(t, l, "packet-mode stateless response chunk did not match',
     "lineReuseBuffer(l, buf);",
     "standalone packet buffer"),
    ("tunnels/TesterClient/downstream/payload.c", "testerclientTunnelDownStreamPayload",
     'testerclientFail(t, l, "packet-mode response chunk did not match',
     "lineReuseBuffer(l, buf);",
     "standalone packet buffer"),
    ("tunnels/TesterClient/downstream/payload.c", "testerclientTunnelDownStreamPayload",
     'testerclientFail(t, l, "response chunk did not match',
     "lineReuseBuffer(l, chunk_buffer);",
     "chunk extracted from the read stream"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverHandlePacketRequestPayload",
     'testerserverFail(t, l, "packet-mode request chunk did not match',
     "lineReuseBuffer(l, buf);",
     "standalone packet buffer"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverHandlePacketStatelessRequestPayload",
     'testerserverFail(t, l, "packet-mode stateless request chunk did not match',
     "lineReuseBuffer(l, buf);",
     "standalone packet buffer"),
    ("tunnels/TesterServer/upstream/payload.c", "testerserverTunnelUpStreamPayload",
     'testerserverFail(t, l, "request chunk did not match',
     "lineReuseBuffer(l, chunk_buffer);",
     "chunk extracted from the read stream"),
]


# Retryable worker paths: an operational rejection of one line is local. These
# must call none of the three process-exit APIs and must return locally.
#
#   (relative path, function, ordered snippets, description)

RETRYABLE_LOCAL = [
    ("tunnels/WireGuardDevice/instance/start.c", "wireguarddeviceQueueWorkerTransportLineInit",
     ("WireGuardDevice: worker transport line was rejected at startup",
      "return;"),
     "one transport line may be rejected and retried on a later output"),
]


# Synchronous startup failures propagate through the bounded startup-result
# collector. They do not request process shutdown from inside a startup stage
# and must never appear in the Category-B manifest.
#
#   (relative path, function, expected startupFailureRecord count, description)

MAIN_THREAD_STARTUP = [
    ("tunnels/PacketSender/common/helpers.c", "packetsenderPrepareRuntime", 13,
     "prepare-time validation and materialization"),
    ("tunnels/AuthenticationServer/instance/start.c", "authenticationserverTunnelOnStart", 2,
     "direct main-thread onStart timer creation"),
    ("tunnels/SpeedTestClient/instance/start.c", "speedtestclientTunnelOnStart", 1,
     "startup message allocation"),
    ("tunnels/TesterClient/instance/prepair.c", "testerclientTunnelOnPrepair", 2,
     "prepare-time validation"),
    ("tunnels/TesterServer/instance/prepair.c", "testerserverTunnelOnPrepair", 1,
     "prepare-time validation"),
    ("ww/managers/socket_manager.c", "listenTcpSinglePort", 1,
     "main-thread listener publication"),
    ("ww/managers/socket_manager.c", "installPendingIptablesRules", 7,
     "main-thread iptables publication"),
]


PROCESS_EXIT_CALLS = ("abortProgramNow", "requestProgramShutdown", "terminateProgram")
VERDICT_HELPERS = ("testerclientFail", "testerserverFail")

_REQUEST_CALL_RE = re.compile(r"\brequestProgramShutdown\s*\(")
_STARTUP_FAILURE_RE = re.compile(r"\bstartupFailureRecord\s*\(")
_HARD_ABORT_RE = re.compile(r"\babortProgramNow\s*\(\s*1\s*\)\s*;")
_BRANCH_CALL_RE = re.compile(
    r"\b(%s)\s*\(" % "|".join(PROCESS_EXIT_CALLS + VERDICT_HELPERS)
)

_FILE_CACHE = {}


def read_source(rel_path, source_overrides):
    if source_overrides and rel_path in source_overrides:
        return source_overrides[rel_path]
    if rel_path not in _FILE_CACHE:
        full_path = os.path.join(ROOT, rel_path)
        if not os.path.exists(full_path):
            return None
        with open(full_path, "r", encoding="utf-8") as handle:
            _FILE_CACHE[rel_path] = handle.read()
    return _FILE_CACHE[rel_path]


def _close_paren(masked, open_paren):
    depth = 0
    for i in range(open_paren, len(masked)):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def request_sites(masked, source, span):
    """Return (sites, problems) for every requestProgramShutdown() in a body.

    A site is well formed when the call is negated and its failure branch opens
    immediately and reaches abortProgramNow(1) before that branch closes, which
    is the required

        if (! requestProgramShutdown(code))
        {
            abortProgramNow(1);
        }

    shape. A leading condition (``x && ! requestProgramShutdown(1)``) and a
    resource release before the fallback are both allowed; anything else is
    reported.
    """
    sites = []
    problems = []

    for match in _REQUEST_CALL_RE.finditer(masked, span[0], span[1]):
        start = match.start()
        prefix = masked[span[0]:start].rstrip()
        if not prefix.endswith("!"):
            problems.append("the result of requestProgramShutdown() at line %d is not tested with `!`"
                            % line_of(source, start))
            continue

        close = _close_paren(masked, match.end() - 1)
        if close < 0 or close >= span[1]:
            problems.append("unterminated requestProgramShutdown() call at line %d" % line_of(source, start))
            continue

        code = " ".join(source[match.end():close].split())

        # The failure branch must open before anything else and must reach the
        # hard fallback before it closes again.
        rest = masked[close + 1:span[1]]
        open_brace = rest.find("{")
        if open_brace < 0:
            problems.append("requestProgramShutdown() at line %d has no failure branch"
                            % line_of(source, start))
            continue

        close_brace = rest.find("}", open_brace)
        branch = rest[open_brace:close_brace if close_brace >= 0 else len(rest)]
        if not _HARD_ABORT_RE.search(branch):
            problems.append("requestProgramShutdown() at line %d has no abortProgramNow(1) fallback"
                            % line_of(source, start))
            continue

        sites.append((start, code))

    return sites, problems


def snippet_positions(source, span, snippets):
    """Match ``snippets`` as an in-order subsequence of the body.

    Returns ``(positions, missing_index)``. ``positions`` holds the ``(start,
    end)`` offsets of each snippet matched so far, so a mutation can delete
    exactly the occurrence this policy depends on rather than an unrelated
    earlier one with the same text.
    """
    positions = []
    cursor = span[0]
    for index, snippet in enumerate(snippets):
        found = source.find(snippet, cursor, span[1])
        if found < 0:
            return positions, index
        positions.append((found, found + len(snippet)))
        cursor = found + len(snippet)
    return positions, -1


def branch_window_end(masked, start, limit):
    """End of the branch that ``start`` sits in: its first closing brace."""
    closing = masked.find("}", start, limit)
    return limit if closing < 0 else closing


# ---------------------------------------------------------------------------
# Policy verification
# ---------------------------------------------------------------------------

def _resolve(rel_path, function, label, errors, source_overrides):
    content = read_source(rel_path, source_overrides)
    if content is None:
        errors.append("[%s] Source file missing: %s" % (label, rel_path))
        return None, None
    span = resolve_function(content, rel_path, function, label, errors)
    if span is None:
        return None, None
    return content, span


def verify_policy(source_overrides=None):
    errors = []
    checked = {"category_b": 0, "requests": 0, "callers": 0, "invariants": 0,
               "recycles": 0, "retryable": 0, "startup": 0}

    category_b_keys = set()

    for rel_path, function, codes, anchors, description in CATEGORY_B:
        label = "Category-B: %s" % description
        key = (rel_path, function)
        if key in category_b_keys:
            errors.append("Duplicate Category-B entry for %s::%s" % key)
            continue
        category_b_keys.add(key)

        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["category_b"] += 1
        masked, _ = analyze(content)
        body_line = line_of(content, span[0])

        # 3: a converted site may never fall back to the legacy entry point.
        retained = count_calls(masked, span, "terminateProgram")
        if retained != 0:
            errors.append("[%s] %s::%s (line %d) still calls terminateProgram() %d time(s)"
                          % (label, rel_path, function, body_line, retained))

        # 1 & 2: every request is present, negated and paired with a fallback.
        sites, problems = request_sites(masked, content, span)
        for problem in problems:
            errors.append("[%s] %s::%s: %s" % (label, rel_path, function, problem))

        actual_codes = tuple(code for _offset, code in sites)
        if actual_codes != tuple(codes):
            errors.append("[%s] %s::%s (line %d) has request/fallback exit codes %r, expected %r"
                          % (label, rel_path, function, body_line, actual_codes, tuple(codes)))
            continue

        checked["requests"] += len(sites)

        # A Category-B function carries exactly one hard abort per request: the
        # fallback. A stray abort here would be an unclassified Category-D site.
        aborts = len(_HARD_ABORT_RE.findall(masked, span[0], span[1]))
        if aborts != len(sites):
            errors.append("[%s] %s::%s (line %d) has %d abortProgramNow(1) call(s) for %d request(s); "
                          "mixed classifications belong in separate functions"
                          % (label, rel_path, function, body_line, aborts, len(sites)))

        # 4: the diagnostic and the cleanup this callback owns come first.
        first_request = sites[0][0]
        _positions, missing = snippet_positions(content, (span[0], first_request), anchors)
        if missing >= 0:
            errors.append("[%s] %s::%s (line %d) is missing anchor %r before its first request "
                          "(or it moved after it)"
                          % (label, rel_path, function, body_line, anchors[missing]))

    # 5: a caller must stop as soon as a helper reports shutdown-requested.
    for rel_path, function, snippets, description in CALLER_STOPS:
        label = "caller stop: %s" % description
        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["callers"] += 1
        _positions, missing = snippet_positions(content, span, snippets)
        if missing >= 0:
            errors.append("[%s] %s::%s (line %d) is missing %r, or it no longer follows the "
                          "preceding step" % (label, rel_path, function,
                                              line_of(content, span[0]), snippets[missing]))

    # 6: a tester invariant hard-aborts and never reaches the verdict helper.
    for rel_path, function, anchor, description in TESTER_INVARIANTS:
        label = "invariant: %s" % description
        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["invariants"] += 1
        anchor_at = content.find(anchor, span[0], span[1])
        if anchor_at < 0:
            errors.append("[%s] %s::%s lost the invariant diagnostic %r"
                          % (label, rel_path, function, anchor))
            continue

        masked, _ = analyze(content)
        # Bounded to the branch the diagnostic sits in, so a hard abort in a
        # neighbouring branch can never satisfy this one.
        window_end = branch_window_end(masked, anchor_at, span[1])
        following = _BRANCH_CALL_RE.search(masked, anchor_at, window_end)
        if following is None:
            errors.append("[%s] %s::%s: %r is no longer followed by a termination call in its own branch"
                          % (label, rel_path, function, anchor))
            continue

        if following.group(1) != "abortProgramNow":
            errors.append("[%s] %s::%s: %r is followed by %s(), but an invariant must hard-abort"
                          % (label, rel_path, function, anchor, following.group(1)))
            continue

        if not _HARD_ABORT_RE.match(masked, following.start()):
            errors.append("[%s] %s::%s: %r is followed by abortProgramNow() with a non-1 exit code"
                          % (label, rel_path, function, anchor))

    # A buffer the callback still owns is recycled before the verdict.
    for rel_path, function, verdict, recycle, description in RECYCLE_BEFORE_VERDICT:
        label = "buffer ownership: %s" % description
        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["recycles"] += 1
        verdict_at = content.find(verdict, span[0], span[1])
        if verdict_at < 0:
            errors.append("[%s] %s::%s lost the verdict call %r" % (label, rel_path, function, verdict))
            continue

        recycle_at = content.rfind(recycle, span[0], verdict_at)
        if recycle_at < 0:
            errors.append("[%s] %s::%s: %r is not recycled before %r"
                          % (label, rel_path, function, recycle, verdict))
            continue

        # The recycle must belong to this verdict's own branch: a recycle from an
        # earlier branch is separated from it by that branch's closing brace.
        masked, _ = analyze(content)
        if masked.find("}", recycle_at, verdict_at) >= 0:
            errors.append("[%s] %s::%s: the %r before %r belongs to an earlier branch"
                          % (label, rel_path, function, recycle, verdict))

    # 7: a retryable rejection stays local.
    for rel_path, function, snippets, description in RETRYABLE_LOCAL:
        label = "retryable: %s" % description
        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["retryable"] += 1
        masked, _ = analyze(content)
        for call_name in PROCESS_EXIT_CALLS:
            used = count_calls(masked, span, call_name)
            if used != 0:
                errors.append("[%s] %s::%s calls %s() %d time(s); one rejected line is not a "
                              "process-wide failure" % (label, rel_path, function, call_name, used))

        _positions, missing = snippet_positions(content, span, snippets)
        if missing >= 0:
            errors.append("[%s] %s::%s is missing %r" % (label, rel_path, function, snippets[missing]))

    # 8: synchronous startup failures report status to the top-level owner.
    for rel_path, function, expected, description in MAIN_THREAD_STARTUP:
        label = "startup failure: %s" % description
        if (rel_path, function) in category_b_keys:
            errors.append("[%s] %s::%s is a main-thread startup site and must not be in the "
                          "Category-B manifest" % (label, rel_path, function))
            continue

        content, span = _resolve(rel_path, function, label, errors, source_overrides)
        if span is None:
            continue

        checked["startup"] += 1
        masked, _ = analyze(content)
        actual = len(_STARTUP_FAILURE_RE.findall(masked, span[0], span[1]))
        if actual != expected:
            errors.append("[%s] %s::%s has %d startupFailureRecord() call(s), expected %d"
                          % (label, rel_path, function, actual, expected))

        for call_name in PROCESS_EXIT_CALLS:
            used = count_calls(masked, span, call_name)
            if used != 0:
                errors.append("[%s] %s::%s calls %s() %d time(s); startup stages must propagate status"
                              % (label, rel_path, function, call_name, used))

    return errors, checked


# ---------------------------------------------------------------------------
# Mutation testing
# ---------------------------------------------------------------------------

def _body(content, function):
    _masked, definitions = analyze(content)
    return definitions[function][0]


def mutate_drop_request(content, function):
    """Neutralize the orderly request while leaving the fallback branch."""
    masked = analyze(content)[0]
    span = _body(content, function)
    match = _REQUEST_CALL_RE.search(masked, span[0], span[1])
    close = _close_paren(masked, match.end() - 1)
    return content[:match.start()] + "false" + content[close + 1:]


def mutate_drop_fallback(content, function):
    masked = analyze(content)[0]
    span = _body(content, function)
    match = _HARD_ABORT_RE.search(masked, span[0], span[1])
    return content[:match.start()] + content[match.end():]


def mutate_drop_ordered_snippet(content, function, snippets, index):
    """Delete exactly the occurrence the ordered policy check matched."""
    span = _body(content, function)
    positions, missing = snippet_positions(content, span, snippets)
    if missing >= 0:
        raise AssertionError("snippet %r not found in %s()" % (snippets[missing], function))
    start, end = positions[index]
    return content[:start] + content[end:]


def mutate_drop_recycle(content, function, verdict, recycle):
    """Delete the recycle that guards this verdict, not an earlier one."""
    span = _body(content, function)
    verdict_at = content.find(verdict, span[0], span[1])
    if verdict_at < 0:
        raise AssertionError("verdict %r not found in %s()" % (verdict, function))
    start = content.rfind(recycle, span[0], verdict_at)
    if start < 0:
        raise AssertionError("recycle %r not found in %s()" % (recycle, function))
    return content[:start] + content[start + len(recycle):]


def mutate_drop_call(content, function, call):
    span = _body(content, function)
    start = content.find(call, span[0], span[1])
    if start < 0:
        raise AssertionError("call %r not found in %s()" % (call, function))
    return content[:start] + content[start + len(call):]


def _invariant_abort_match(content, function, anchor):
    """The hard abort inside the branch that carries ``anchor``."""
    masked = analyze(content)[0]
    span = _body(content, function)
    anchor_at = content.find(anchor, span[0], span[1])
    if anchor_at < 0:
        raise AssertionError("anchor %r not found in %s()" % (anchor, function))
    window_end = branch_window_end(masked, anchor_at, span[1])
    match = _HARD_ABORT_RE.search(masked, anchor_at, window_end)
    if match is None:
        raise AssertionError("no abort follows %r in %s()" % (anchor, function))
    return match


def mutate_drop_abort_after(content, function, anchor):
    """Delete the hard abort that follows an invariant diagnostic."""
    match = _invariant_abort_match(content, function, anchor)
    return content[:match.start()] + content[match.end():]


class MutationRunner:
    def __init__(self):
        self.applied = 0
        self.escaped = []

    def expect_failure(self, label, rel_path, mutated):
        self.applied += 1
        errors, _checked = verify_policy({rel_path: mutated})
        if not errors:
            self.escaped.append(label)


def run_mutation_tests():
    print("Running mutation tests on the orderly-shutdown checker...")
    runner = MutationRunner()

    # 1 & 2: the request and its fallback must each be independently required.
    for rel_path, function, _codes, _anchors, _description in CATEGORY_B:
        content = read_source(rel_path, None)
        runner.expect_failure("%s::%s drop orderly request" % (rel_path, function),
                              rel_path, mutate_drop_request(content, function))
        runner.expect_failure("%s::%s drop hard fallback" % (rel_path, function),
                              rel_path, mutate_drop_fallback(content, function))

    # 3: the immediate caller return must be required.
    for rel_path, function, snippets, _description in CALLER_STOPS:
        content = read_source(rel_path, None)
        for index, snippet in enumerate(snippets):
            if not snippet.startswith("return"):
                continue
            runner.expect_failure(
                "%s::%s drop %r at step %d" % (rel_path, function, snippet, index + 1),
                rel_path, mutate_drop_ordered_snippet(content, function, snippets, index))

    # 4: one pre-request buffer recycle must be required.
    for rel_path, function, verdict, recycle, _description in RECYCLE_BEFORE_VERDICT:
        content = read_source(rel_path, None)
        runner.expect_failure(
            "%s::%s drop %r before %r" % (rel_path, function, recycle, verdict[:44]),
            rel_path, mutate_drop_recycle(content, function, verdict, recycle))

    # 5: one tester invariant abort must be required, and downgrading it to the
    #    orderly verdict helper must be rejected too.
    for rel_path, function, anchor, _description in TESTER_INVARIANTS:
        content = read_source(rel_path, None)
        runner.expect_failure(
            "%s::%s drop the abort after %r" % (rel_path, function, anchor[:48]),
            rel_path, mutate_drop_abort_after(content, function, anchor))

        helper = "testerserverFail" if "TesterServer" in rel_path else "testerclientFail"
        match = _invariant_abort_match(content, function, anchor)
        downgraded = content[:match.start()] + "%s(t, l, \"x\");" % helper + content[match.end():]
        runner.expect_failure(
            "%s::%s downgrade the abort after %r to %s()" % (rel_path, function, anchor[:32], helper),
            rel_path, downgraded)

    # 6: the WireGuard local return must be required, and any process-exit API
    #    smuggled into that path must be rejected.
    for rel_path, function, snippets, _description in RETRYABLE_LOCAL:
        content = read_source(rel_path, None)
        for index, snippet in enumerate(snippets):
            if not snippet.startswith("return"):
                continue
            runner.expect_failure("%s::%s drop %r" % (rel_path, function, snippet),
                                  rel_path,
                                  mutate_drop_ordered_snippet(content, function, snippets, index))

        span = _body(content, function)
        for call_name in PROCESS_EXIT_CALLS:
            injected = content[:span[0] + 1] + "\n    %s(1);" % call_name + content[span[0] + 1:]
            runner.expect_failure("%s::%s gained %s()" % (rel_path, function, call_name),
                                  rel_path, injected)

    # 7: a startup site must not silently lose its explicit status report.
    for rel_path, function, _expected, _description in MAIN_THREAD_STARTUP:
        content = read_source(rel_path, None)
        runner.expect_failure("%s::%s drop one startupFailureRecord()" % (rel_path, function),
                              rel_path, mutate_drop_call(content, function, "startupFailureRecord(1);"))

    if runner.escaped:
        print("Mutation testing FAILED: %d mutation(s) were not detected:" % len(runner.escaped))
        for label in runner.escaped:
            print("  - %s" % label)
        return False

    print("  %d mutations applied, all detected." % runner.applied)
    return True


def main():
    errors, checked = verify_policy()

    if errors:
        print("Orderly Shutdown Policy Check FAILED with %d error(s):" % len(errors))
        for error in errors:
            print("  - %s" % error)
        sys.exit(1)

    print("Orderly Shutdown Policy Check PASSED: %d request/fallback site(s) across %d Category-B "
          "function(s), %d caller stop(s), %d tester invariant(s), %d buffer-ownership site(s), "
          "%d retryable path(s), %d startup-status site(s)."
          % (checked["requests"], checked["category_b"], checked["callers"], checked["invariants"],
             checked["recycles"], checked["retryable"], checked["startup"]))

    if "--mutation-test" in sys.argv or "-m" in sys.argv:
        if not run_mutation_tests():
            sys.exit(1)


if __name__ == "__main__":
    main()
