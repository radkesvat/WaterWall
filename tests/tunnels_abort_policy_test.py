#!/usr/bin/env python3
"""Category-D hard-abort source policy checker for tunnels and shared guards.

Every Category-D site is identified by (relative source path, exact function
name) and never by a line number: line proximity let a neighbouring abort
satisfy a candidate whose own abort had been deleted.

Function bodies are extracted with a small lexical C scanner (standard library
only) that blanks comments, string literals and character literals before any
call is counted, so none of the following can satisfy a candidate:

    abortProgramNow(0);
    abortProgramNow(code);
    // abortProgramNow(1);
    "abortProgramNow(1)";
    void abortProgramNow(int);

Usage:
    python3 tests/tunnels_abort_policy_test.py [--mutation-test|-m]
"""
import os
import re
import sys

# Root repository directory
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Total number of audited Category-D conversions. The manifest must account for
# every one of them.
EXPECTED_TOTAL_ABORTS = 230


# ---------------------------------------------------------------------------
# Lexical C scanning
# ---------------------------------------------------------------------------

def mask_source(src):
    """Blank out comments, string literals and character literals.

    The result has exactly the same length as ``src`` and keeps every newline,
    so offsets and line numbers computed on the masked text remain valid for
    the original text.
    """
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
        elif c == '"' or c == "'":
            quote = c
            out[i] = " "
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if src[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _brace_depths(masked):
    depths = [0] * (len(masked) + 1)
    depth = 0
    for i, c in enumerate(masked):
        depths[i] = depth
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
    depths[len(masked)] = depth
    return depths


def _match_pair(masked, start, open_char, close_char):
    depth = 0
    for i in range(start, len(masked)):
        if masked[i] == open_char:
            depth += 1
        elif masked[i] == close_char:
            depth -= 1
            if depth == 0:
                return i
    return -1


_IDENT_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONTROL_KEYWORDS = frozenset(
    ("if", "for", "while", "switch", "return", "sizeof", "defined", "do", "else", "case")
)


def find_function_definitions(masked):
    """Map every file-scope function definition name to its body span(s).

    A body span is the half-open ``(start, end)`` offset pair covering the
    outermost ``{ ... }`` block, so the returned spans can be used directly to
    slice either the masked or the original source.
    """
    depths = _brace_depths(masked)
    definitions = {}
    for match in _IDENT_CALL_RE.finditer(masked):
        name = match.group(1)
        if name in _CONTROL_KEYWORDS:
            continue
        if depths[match.start()] != 0:
            continue
        close_paren = _match_pair(masked, match.end() - 1, "(", ")")
        if close_paren < 0:
            continue
        cursor = close_paren + 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        if cursor >= len(masked) or masked[cursor] != "{":
            continue
        body_end = _match_pair(masked, cursor, "{", "}")
        if body_end < 0:
            continue
        definitions.setdefault(name, []).append((cursor, body_end + 1))
    return definitions


def line_of(src, offset):
    return src.count("\n", 0, offset) + 1


def _call_re(name):
    return re.compile(r"\b%s\s*\(" % re.escape(name))


_ABORT_ANY_RE = _call_re("abortProgramNow")
_ABORT_HARD_RE = re.compile(r"\babortProgramNow\s*\(\s*1\s*\)\s*;")
_TERMINATE_RE = _call_re("terminateProgram")
_REQUEST_SHUTDOWN_RE = _call_re("requestProgramShutdown")

_CALL_PATTERNS = {
    "abortProgramNow": _ABORT_ANY_RE,
    "terminateProgram": _TERMINATE_RE,
    "requestProgramShutdown": _REQUEST_SHUTDOWN_RE,
}


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
#
# Each entry is:
#   (relative path,
#    exact function name,
#    number of abortProgramNow(1) calls expected in that function,
#    stable diagnostic anchors identifying the intended invariant branches,
#    short classification description)
#
# Candidates that share one function are aggregated into a single entry, so the
# expected count is the authority on how many aborts that function must keep.

MANIFEST = [
    ("ww/net/adapter.c", "disabledPayloadRoutine", 1,
     ("Illegal call to payload routine on Adapter",),
     "shared adapter edge guard: impossible payload callback"),
    ("ww/net/adapter.c", "disabledRoutine", 1,
     ("Illegal call to routine on Adapter",),
     "shared adapter edge guard: impossible non-payload callback"),
    ("ww/net/adapter.c", "adapterCreate", 1,
     ("adapterCreate received invalid edge value",),
     "shared adapter edge guard: invalid edge classification"),
    ("tunnels/AuthenticationClient/downstream/init.c", "authenticationclientTunnelDownStreamInit", 1,
     ("AuthenticationClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: AuthenticationClient downstream/init.c"),
    ("tunnels/AuthenticationClient/upstream/init.c", "authenticationclientTunnelUpStreamInit", 1,
     ("AuthenticationClient: UpStreamInit is disabled; this node owns its control line",),
     "impossible flow-callback stub: AuthenticationClient upstream/init.c"),
    ("tunnels/AuthenticationClient/upstream/est.c", "authenticationclientTunnelUpStreamEst", 1,
     ("AuthenticationClient: UpStreamEst is disabled",),
     "impossible flow-callback stub: AuthenticationClient upstream/est.c"),
    ("tunnels/AuthenticationClient/upstream/payload.c", "authenticationclientTunnelUpStreamPayload", 1,
     ("AuthenticationClient: UpStreamPayload is disabled",),
     "impossible flow-callback stub: AuthenticationClient upstream/payload.c"),
    ("tunnels/AuthenticationClient/upstream/pause.c", "authenticationclientTunnelUpStreamPause", 1,
     ("AuthenticationClient: UpStreamPause is disabled",),
     "impossible flow-callback stub: AuthenticationClient upstream/pause.c"),
    ("tunnels/AuthenticationClient/upstream/resume.c", "authenticationclientTunnelUpStreamResume", 1,
     ("AuthenticationClient: UpStreamResume is disabled",),
     "impossible flow-callback stub: AuthenticationClient upstream/resume.c"),
    ("tunnels/AuthenticationClient/upstream/fin.c", "authenticationclientTunnelUpStreamFinish", 1,
     ("AuthenticationClient: UpStreamFinish is disabled",),
     "impossible flow-callback stub: AuthenticationClient upstream/fin.c"),
    ("tunnels/AuthenticationServer/upstream/est.c", "authenticationserverTunnelUpStreamEst", 1,
     ("AuthenticationServer: UpStreamEst is disabled",),
     "impossible flow-callback stub: AuthenticationServer upstream/est.c"),
    ("tunnels/AuthenticationServer/downstream/init.c", "authenticationserverTunnelDownStreamInit", 1,
     ("AuthenticationServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/init.c"),
    ("tunnels/AuthenticationServer/downstream/est.c", "authenticationserverTunnelDownStreamEst", 1,
     ("AuthenticationServer: DownStreamEst is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/est.c"),
    ("tunnels/AuthenticationServer/downstream/payload.c", "authenticationserverTunnelDownStreamPayload", 1,
     ("AuthenticationServer: DownStreamPayload is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/payload.c"),
    ("tunnels/AuthenticationServer/downstream/pause.c", "authenticationserverTunnelDownStreamPause", 1,
     ("AuthenticationServer: DownStreamPause is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/pause.c"),
    ("tunnels/AuthenticationServer/downstream/resume.c", "authenticationserverTunnelDownStreamResume", 1,
     ("AuthenticationServer: DownStreamResume is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/resume.c"),
    ("tunnels/AuthenticationServer/downstream/fin.c", "authenticationserverTunnelDownStreamFinish", 1,
     ("AuthenticationServer: DownStreamFinish is disabled",),
     "impossible flow-callback stub: AuthenticationServer downstream/fin.c"),
    ("tunnels/Bgp4Client/downstream/init.c", "bgp4clientTunnelDownStreamInit", 1,
     ("Bgp4Client: DownStreamInit is disabled",),
     "impossible flow-callback stub: Bgp4Client downstream/init.c"),
    ("tunnels/Bgp4Client/upstream/est.c", "bgp4clientTunnelUpStreamEst", 1,
     ("Bgp4Client: UpStreamEst is disabled",),
     "impossible flow-callback stub: Bgp4Client upstream/est.c"),
    ("tunnels/Bgp4Server/downstream/init.c", "bgp4serverTunnelDownStreamInit", 1,
     ("Bgp4Server: DownStreamInit is disabled",),
     "impossible flow-callback stub: Bgp4Server downstream/init.c"),
    ("tunnels/Bgp4Server/upstream/est.c", "bgp4serverTunnelUpStreamEst", 1,
     ("Bgp4Server: UpStreamEst is disabled",),
     "impossible flow-callback stub: Bgp4Server upstream/est.c"),
    ("tunnels/ConnectionFisherClient/downstream/init.c", "connectionfisherclientTunnelDownStreamInit", 1,
     ("ConnectionFisherClient: downstream init disabled",),
     "impossible flow-callback stub: ConnectionFisherClient downstream/init.c"),
    ("tunnels/ConnectionFisherClient/upstream/est.c", "connectionfisherclientTunnelUpStreamEst", 1,
     ("ConnectionFisherClient: upstream est disabled",),
     "impossible flow-callback stub: ConnectionFisherClient upstream/est.c"),
    ("tunnels/ConnectionFisherServer/downstream/init.c", "connectionfisherserverTunnelDownStreamInit", 1,
     ("ConnectionFisherServer: downstream init disabled",),
     "impossible flow-callback stub: ConnectionFisherServer downstream/init.c"),
    ("tunnels/ConnectionFisherServer/upstream/est.c", "connectionfisherserverTunnelUpStreamEst", 1,
     ("ConnectionFisherServer: upstream est disabled",),
     "impossible flow-callback stub: ConnectionFisherServer upstream/est.c"),
    ("tunnels/EncryptionClient/downstream/init.c", "encryptionclientTunnelDownStreamInit", 1,
     ("EncryptionClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: EncryptionClient downstream/init.c"),
    ("tunnels/EncryptionClient/upstream/est.c", "encryptionclientTunnelUpStreamEst", 1,
     ("EncryptionClient: UpstreamEst is disabled",),
     "impossible flow-callback stub: EncryptionClient upstream/est.c"),
    ("tunnels/EncryptionServer/downstream/init.c", "encryptionserverTunnelDownStreamInit", 1,
     ("EncryptionServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: EncryptionServer downstream/init.c"),
    ("tunnels/EncryptionServer/upstream/est.c", "encryptionserverTunnelUpStreamEst", 1,
     ("EncryptionServer: UpstreamEst is disabled",),
     "impossible flow-callback stub: EncryptionServer upstream/est.c"),
    ("tunnels/HalfDuplexClient/downstream/init.c", "halfduplexclientTunnelDownStreamInit", 1,
     ("HalfDuplexClient will not receive a backward init",),
     "impossible flow-callback stub: HalfDuplexClient downstream/init.c"),
    ("tunnels/HalfDuplexClient/upstream/est.c", "halfduplexclientTunnelUpStreamEst", 1,
     ("HalfDuplexClient will not receive a upstream est",),
     "impossible flow-callback stub: HalfDuplexClient upstream/est.c"),
    ("tunnels/HalfDuplexServer/downstream/init.c", "halfduplexserverTunnelDownStreamInit", 1,
     ("HalfDuplexServer is not supposed to receive downstream init",),
     "impossible flow-callback stub: HalfDuplexServer downstream/init.c"),
    ("tunnels/HalfDuplexServer/upstream/est.c", "halfduplexserverTunnelUpStreamEst", 1,
     ("HalfDuplexServer is not supposed to receive upstream EST",),
     "impossible flow-callback stub: HalfDuplexServer upstream/est.c"),
    ("tunnels/HeaderClient/downstream/init.c", "headerclientTunnelDownStreamInit", 1,
     ("HeaderClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: HeaderClient downstream/init.c"),
    ("tunnels/HeaderClient/upstream/est.c", "headerclientTunnelUpStreamEst", 1,
     ("HeaderClient: UpStreamEst is disabled",),
     "impossible flow-callback stub: HeaderClient upstream/est.c"),
    ("tunnels/HeaderServer/downstream/init.c", "headerserverTunnelDownStreamInit", 1,
     ("HeaderServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: HeaderServer downstream/init.c"),
    ("tunnels/HeaderServer/upstream/est.c", "headerserverTunnelUpStreamEst", 1,
     ("HeaderServer: UpStreamEst is disabled",),
     "impossible flow-callback stub: HeaderServer upstream/est.c"),
    ("tunnels/IpManipulator/upstream/est.c", "ipmanipulatorUpStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator upstream/est.c"),
    ("tunnels/IpManipulator/upstream/fin.c", "ipmanipulatorUpStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator upstream/fin.c"),
    ("tunnels/IpManipulator/upstream/pause.c", "ipmanipulatorUpStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator upstream/pause.c"),
    ("tunnels/IpManipulator/upstream/resume.c", "ipmanipulatorUpStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator upstream/resume.c"),
    ("tunnels/IpManipulator/downstream/est.c", "ipmanipulatorDownStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator downstream/est.c"),
    ("tunnels/IpManipulator/downstream/fin.c", "ipmanipulatorDownStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator downstream/fin.c"),
    ("tunnels/IpManipulator/downstream/pause.c", "ipmanipulatorDownStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator downstream/pause.c"),
    ("tunnels/IpManipulator/downstream/resume.c", "ipmanipulatorDownStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpManipulator)",),
     "impossible flow-callback stub: IpManipulator downstream/resume.c"),
    ("tunnels/IpOverrider/upstream/init.c", "ipoverriderUpStreamInit", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider upstream/init.c"),
    ("tunnels/IpOverrider/upstream/est.c", "ipoverriderUpStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider upstream/est.c"),
    ("tunnels/IpOverrider/upstream/fin.c", "ipoverriderUpStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider upstream/fin.c"),
    ("tunnels/IpOverrider/upstream/pause.c", "ipoverriderUpStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider upstream/pause.c"),
    ("tunnels/IpOverrider/upstream/resume.c", "ipoverriderUpStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider upstream/resume.c"),
    ("tunnels/IpOverrider/downstream/est.c", "ipoverriderDownStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider downstream/est.c"),
    ("tunnels/IpOverrider/downstream/fin.c", "ipoverriderDownStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider downstream/fin.c"),
    ("tunnels/IpOverrider/downstream/pause.c", "ipoverriderDownStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider downstream/pause.c"),
    ("tunnels/IpOverrider/downstream/resume.c", "ipoverriderDownStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (IpOverrider)",),
     "impossible flow-callback stub: IpOverrider downstream/resume.c"),
    ("tunnels/KeepAliveClient/downstream/init.c", "keepaliveclientTunnelDownStreamInit", 1,
     ("KeepAliveClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: KeepAliveClient downstream/init.c"),
    ("tunnels/KeepAliveServer/downstream/init.c", "keepaliveserverTunnelDownStreamInit", 1,
     ("KeepAliveServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: KeepAliveServer downstream/init.c"),
    ("tunnels/MuxClient/downstream/init.c", "muxclientTunnelDownStreamInit", 1,
     ("MuxClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: MuxClient downstream/init.c"),
    ("tunnels/MuxClient/upstream/est.c", "muxclientTunnelUpStreamEst", 1,
     ("MuxClient: UpStreamEst is disabled",),
     "impossible flow-callback stub: MuxClient upstream/est.c"),
    ("tunnels/MuxServer/downstream/init.c", "muxserverTunnelDownStreamInit", 1,
     ("MuxServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: MuxServer downstream/init.c"),
    ("tunnels/MuxServer/upstream/est.c", "muxserverTunnelUpStreamEst", 1,
     ("MuxServer: UpStreamEst is disabled",),
     "impossible flow-callback stub: MuxServer upstream/est.c"),
    ("tunnels/PacketSplitStream/upstream/fin.c", "packetsplitstreamTunnelUpStreamFinish", 1,
     ("packetsplitstreamTunnelUpStreamFinish is not supposed to be called",),
     "impossible flow-callback stub: PacketSplitStream upstream/fin.c"),
    ("tunnels/PacketSplitStream/downstream/fin.c", "packetsplitstreamTunnelDownStreamFinish", 1,
     ("packetsplitstreamTunnelDownStreamFinish is not supposed to be called",),
     "impossible flow-callback stub: PacketSplitStream downstream/fin.c"),
    ("tunnels/PacketsToConnection/downstream/init.c", "ptcTunnelDownStreamInit", 1,
     ("Impossible call",),
     "impossible flow-callback stub: PacketsToConnection downstream/init.c"),
    ("tunnels/PacketsToConnection/upstream/est.c", "ptcTunnelUpStreamEst", 1,
     ("PacketsToConnection: unexpected upstream Est on the packet line",),
     "impossible flow-callback stub: PacketsToConnection upstream/est.c"),
    ("tunnels/PacketsToConnection/upstream/fin.c", "ptcTunnelUpStreamFinish", 1,
     ("PacketsToConnection: unexpected upstream Finish on the packet line",),
     "impossible flow-callback stub: PacketsToConnection upstream/fin.c"),
    ("tunnels/PacketsToConnection/upstream/pause.c", "ptcTunnelUpStreamPause", 1,
     ("PacketsToConnection: unexpected upstream Pause on the packet line",),
     "impossible flow-callback stub: PacketsToConnection upstream/pause.c"),
    ("tunnels/PacketsToConnection/upstream/resume.c", "ptcTunnelUpStreamResume", 1,
     ("PacketsToConnection: unexpected upstream Resume on the packet line",),
     "impossible flow-callback stub: PacketsToConnection upstream/resume.c"),
    ("tunnels/PacketsToStream/upstream/fin.c", "packetstostreamTunnelUpStreamFinish", 1,
     ("PacketsToStream: not supposed to receive upstream fin",),
     "impossible flow-callback stub: PacketsToStream upstream/fin.c"),
    ("tunnels/PingClient/upstream/init.c", "pingclientUpStreamInit", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient upstream/init.c"),
    ("tunnels/PingClient/upstream/est.c", "pingclientUpStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient upstream/est.c"),
    ("tunnels/PingClient/upstream/fin.c", "pingclientUpStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient upstream/fin.c"),
    ("tunnels/PingClient/upstream/pause.c", "pingclientUpStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient upstream/pause.c"),
    ("tunnels/PingClient/upstream/resume.c", "pingclientUpStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient upstream/resume.c"),
    ("tunnels/PingClient/downstream/est.c", "pingclientDownStreamEst", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient downstream/est.c"),
    ("tunnels/PingClient/downstream/fin.c", "pingclientDownStreamFinish", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient downstream/fin.c"),
    ("tunnels/PingClient/downstream/pause.c", "pingclientDownStreamPause", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient downstream/pause.c"),
    ("tunnels/PingClient/downstream/resume.c", "pingclientDownStreamResume", 1,
     ("This Function is not supposed to be called, used packet-tunnel interface instead (PingClient)",),
     "impossible flow-callback stub: PingClient downstream/resume.c"),
    ("tunnels/ReverseClient/downstream/init.c", "reverseclientTunnelDownStreamInit", 1,
     ("ReverseClient: DownStreamInit is disabled, this should not be called",),
     "impossible flow-callback stub: ReverseClient downstream/init.c"),
    ("tunnels/ReverseClient/upstream/init.c", "reverseclientTunnelUpStreamInit", 1,
     ("ReverseClient: UpStream Init is disabled",),
     "impossible flow-callback stub: ReverseClient upstream/init.c"),
    ("tunnels/ReverseServer/downstream/est.c", "reverseserverTunnelDownStreamEst", 1,
     ("ReverseServer: Downstream Est is disabled",),
     "impossible flow-callback stub: ReverseServer downstream/est.c"),
    ("tunnels/ReverseServer/upstream/est.c", "reverseserverTunnelUpStreamEst", 1,
     ("reverseserverTunnelUpStreamEst: Upstream Est is disabled",),
     "impossible flow-callback stub: ReverseServer upstream/est.c"),
    ("tunnels/Socks5Client/upstream/est.c", "socks5clientTunnelUpStreamEst", 1,
     ("Socks5Client: UpStreamEst is disabled",),
     "impossible flow-callback stub: Socks5Client upstream/est.c"),
    ("tunnels/Socks5Server/upstream/est.c", "socks5serverTunnelUpStreamEst", 1,
     ("Socks5Server: UpStreamEst is disabled",),
     "impossible flow-callback stub: Socks5Server upstream/est.c"),
    ("tunnels/SoftIpLimiter/downstream/init.c", "softiplimiterTunnelDownStreamInit", 1,
     ("SoftIpLimiter: downstream init disabled",),
     "impossible flow-callback stub: SoftIpLimiter downstream/init.c"),
    ("tunnels/SpeedTestClient/downstream/init.c", "speedtestclientTunnelDownStreamInit", 1,
     ("SpeedTestClient: downstream Init is disabled",),
     "impossible flow-callback stub: SpeedTestClient downstream/init.c"),
    ("tunnels/SpeedTestClient/upstream/init.c", "speedtestclientTunnelUpStreamInit", 1,
     ("SpeedTestClient: upstream Init is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/init.c"),
    ("tunnels/SpeedTestClient/upstream/est.c", "speedtestclientTunnelUpStreamEst", 1,
     ("SpeedTestClient: upstream Est is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/est.c"),
    ("tunnels/SpeedTestClient/upstream/payload.c", "speedtestclientTunnelUpStreamPayload", 1,
     ("SpeedTestClient: upstream Payload is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/payload.c"),
    ("tunnels/SpeedTestClient/upstream/pause.c", "speedtestclientTunnelUpStreamPause", 1,
     ("SpeedTestClient: upstream Pause is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/pause.c"),
    ("tunnels/SpeedTestClient/upstream/resume.c", "speedtestclientTunnelUpStreamResume", 1,
     ("SpeedTestClient: upstream Resume is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/resume.c"),
    ("tunnels/SpeedTestClient/upstream/fin.c", "speedtestclientTunnelUpStreamFinish", 1,
     ("SpeedTestClient: upstream Finish is disabled",),
     "impossible flow-callback stub: SpeedTestClient upstream/fin.c"),
    ("tunnels/SpeedTestServer/upstream/est.c", "speedtestserverTunnelUpStreamEst", 1,
     ("SpeedTestServer: upstream Est is disabled",),
     "impossible flow-callback stub: SpeedTestServer upstream/est.c"),
    ("tunnels/SpeedTestServer/downstream/init.c", "speedtestserverTunnelDownStreamInit", 1,
     ("SpeedTestServer: downstream Init is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/init.c"),
    ("tunnels/SpeedTestServer/downstream/est.c", "speedtestserverTunnelDownStreamEst", 1,
     ("SpeedTestServer: downstream Est is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/est.c"),
    ("tunnels/SpeedTestServer/downstream/payload.c", "speedtestserverTunnelDownStreamPayload", 1,
     ("SpeedTestServer: downstream Payload is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/payload.c"),
    ("tunnels/SpeedTestServer/downstream/pause.c", "speedtestserverTunnelDownStreamPause", 1,
     ("SpeedTestServer: downstream Pause is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/pause.c"),
    ("tunnels/SpeedTestServer/downstream/resume.c", "speedtestserverTunnelDownStreamResume", 1,
     ("SpeedTestServer: downstream Resume is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/resume.c"),
    ("tunnels/SpeedTestServer/downstream/fin.c", "speedtestserverTunnelDownStreamFinish", 1,
     ("SpeedTestServer: downstream Finish is disabled",),
     "impossible flow-callback stub: SpeedTestServer downstream/fin.c"),
    ("tunnels/StreamToPackets/downstream/fin.c", "streamtopacketsTunnelDownStreamFinish", 1,
     ("StreamToPackets: not supposed to receive downstream fin",),
     "impossible flow-callback stub: StreamToPackets downstream/fin.c"),
    ("tunnels/TcpConnector/upstream/est.c", "tcpconnectorTunnelUpStreamEst", 1,
     ("TcpConnector: upStreamEst is not supposed to be called",),
     "impossible flow-callback stub: TcpConnector upstream/est.c"),
    ("tunnels/TcpOverUdpClient/downstream/init.c", "tcpoverudpclientTunnelDownStreamInit", 1,
     ("TcpOverUdpClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: TcpOverUdpClient downstream/init.c"),
    ("tunnels/TcpOverUdpClient/upstream/est.c", "tcpoverudpclientTunnelUpStreamEst", 1,
     ("TcpOverUdpClient: UpstreamEst is disabled",),
     "impossible flow-callback stub: TcpOverUdpClient upstream/est.c"),
    ("tunnels/TcpOverUdpServer/downstream/init.c", "tcpoverudpserverTunnelDownStreamInit", 1,
     ("TcpOverUdpServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: TcpOverUdpServer downstream/init.c"),
    ("tunnels/TcpOverUdpServer/upstream/est.c", "tcpoverudpserverTunnelUpStreamEst", 1,
     ("TcpOverUdpServer: UpstreamEst is disabled",),
     "impossible flow-callback stub: TcpOverUdpServer upstream/est.c"),
    ("tunnels/TesterClient/downstream/init.c", "testerclientTunnelDownStreamInit", 1,
     ("TesterClient: downStreamInit disabled",),
     "impossible flow-callback stub: TesterClient downstream/init.c"),
    ("tunnels/TesterClient/upstream/init.c", "testerclientTunnelUpStreamInit", 1,
     ("TesterClient: upStreamInit disabled",),
     "impossible flow-callback stub: TesterClient upstream/init.c"),
    ("tunnels/TesterClient/upstream/est.c", "testerclientTunnelUpStreamEst", 1,
     ("TesterClient: upStreamEst disabled",),
     "impossible flow-callback stub: TesterClient upstream/est.c"),
    ("tunnels/TesterClient/upstream/payload.c", "testerclientTunnelUpStreamPayload", 1,
     ("TesterClient: upStreamPayload disabled",),
     "impossible flow-callback stub: TesterClient upstream/payload.c"),
    ("tunnels/TesterClient/upstream/pause.c", "testerclientTunnelUpStreamPause", 1,
     ("TesterClient: upStreamPause disabled",),
     "impossible flow-callback stub: TesterClient upstream/pause.c"),
    ("tunnels/TesterClient/upstream/resume.c", "testerclientTunnelUpStreamResume", 1,
     ("TesterClient: upStreamResume disabled",),
     "impossible flow-callback stub: TesterClient upstream/resume.c"),
    ("tunnels/TesterClient/upstream/fin.c", "testerclientTunnelUpStreamFinish", 1,
     ("TesterClient: upStreamFinish disabled",),
     "impossible flow-callback stub: TesterClient upstream/fin.c"),
    ("tunnels/TlsClient/downstream/init.c", "tlsclientTunnelDownStreamInit", 1,
     ("TlsClient: downstream init is disabled",),
     "impossible flow-callback stub: TlsClient downstream/init.c"),
    ("tunnels/TrojanClient/upstream/est.c", "trojanclientTunnelUpStreamEst", 1,
     ("TrojanClient: UpStreamEst is disabled",),
     "impossible flow-callback stub: TrojanClient upstream/est.c"),
    ("tunnels/TrojanServer/upstream/est.c", "trojanserverTunnelUpStreamEst", 1,
     ("TrojanServer: UpStreamEst is disabled",),
     "impossible flow-callback stub: TrojanServer upstream/est.c"),
    ("tunnels/UdpConnector/upstream/est.c", "udpconnectorTunnelUpStreamEst", 1,
     ("UdpConnector: UpStream Est is disabled",),
     "impossible flow-callback stub: UdpConnector upstream/est.c"),
    ("tunnels/UdpListener/downstream/init.c", "udplistenerTunnelDownStreamInit", 1,
     ("UdpListener: DownStream Init is disabled",),
     "impossible flow-callback stub: UdpListener downstream/init.c"),
    ("tunnels/UdpOverTcpClient/downstream/init.c", "udpovertcpclientTunnelDownStreamInit", 1,
     ("UdpOverTcpClient: DownStreamInit is disabled",),
     "impossible flow-callback stub: UdpOverTcpClient downstream/init.c"),
    ("tunnels/UdpOverTcpClient/upstream/est.c", "udpovertcpclientTunnelUpStreamEst", 1,
     ("UdpOverTcpClient: UpstreamEst is disabled",),
     "impossible flow-callback stub: UdpOverTcpClient upstream/est.c"),
    ("tunnels/UdpOverTcpServer/downstream/init.c", "udpovertcpserverTunnelDownStreamInit", 1,
     ("UdpOverTcpServer: DownStreamInit is disabled",),
     "impossible flow-callback stub: UdpOverTcpServer downstream/init.c"),
    ("tunnels/UdpOverTcpServer/upstream/est.c", "udpovertcpserverTunnelUpStreamEst", 1,
     ("UdpOverTcpServer: UpstreamEst is disabled",),
     "impossible flow-callback stub: UdpOverTcpServer upstream/est.c"),
    ("tunnels/VlessClient/upstream/est.c", "vlessclientTunnelUpStreamEst", 1,
     ("VlessClient: UpStreamEst is disabled",),
     "impossible flow-callback stub: VlessClient upstream/est.c"),
    ("tunnels/VlessServer/upstream/est.c", "vlessserverTunnelUpStreamEst", 1,
     ("VlessServer: UpStreamEst is disabled",),
     "impossible flow-callback stub: VlessServer upstream/est.c"),
    ("tunnels/IpManipulator/upstream/init.c", "ipmanipulatorUpStreamInit", 1,
     ("IpManipulator: next packet line died during upstream init",),
     "runtime flow-callback invariant: IpManipulator upstream init packet line died"),
    ("ww/net/packet_tunnel.c", "packettunnelLifecycleAnchorUpstreamFinish", 1,
     ("%s: unexpected upstream Finish on worker packet line %d",),
     "runtime flow-callback invariant: packet lifecycle anchor upstream fin worker packet line"),
    ("ww/net/packet_tunnel.c", "packettunnelLifecycleAnchorDownstreamFinish", 1,
     ("%s: unexpected downstream Finish on worker packet line %d",),
     "runtime flow-callback invariant: packet lifecycle anchor downstream fin worker packet line"),
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientClosePair", 1,
     ("ReverseClient: failed to detach an owned pair from the idle table",),
     "runtime flow-callback invariant: ReverseClient pair idle-table detachment"),
    ("tunnels/ReverseClient/downstream/payload.c", "reverseclientTunnelDownStreamPayload", 1,
     ("ReverseClient: failed to remove an idle pair while activating it",),
     "runtime flow-callback invariant: ReverseClient downstream payload remove starved table"),
    ("tunnels/HalfDuplexServer/upstream/fin.c", "halfduplexserverTunnelUpStreamFinish", 3,
     ("HalfDuplexServer: Thread safety is done incorrectly",
      "HalfDuplexServer: Unexpected"),
     "runtime flow-callback invariant: HalfDuplexServer finish map membership and state"),
    ("tunnels/HalfDuplexServer/upstream/payload.c", "handleUploadInTable", 1,
     ("HalfDuplexServer: Thread safety is done incorrectly",),
     "runtime flow-callback invariant: HalfDuplexServer payload map membership"),
    ("tunnels/TcpConnector/upstream/fin.c", "tcpconnectorTunnelUpStreamFinish", 1,
     ("TcpConnector: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: TcpConnector upstream fin remove idle table"),
    ("tunnels/TcpConnector/upstream/init.c", "tcpconnectorTunnelUpStreamInit", 1,
     ("TcpConnector: internal DomainResolver prepare state is missing",),
     "runtime flow-callback invariant: TcpConnector upstream init missing domain resolver"),
    ("tunnels/TcpConnector/upstream/payload.c", "handleQueueOverflow", 1,
     ("TcpConnector: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: TcpConnector upstream payload remove idle table"),
    ("tunnels/TcpListener/downstream/fin.c", "tcplistenerTunnelDownStreamFinish", 1,
     ("TcpListener: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: TcpListener downstream fin remove idle table"),
    ("tunnels/TcpListener/downstream/payload.c", "handleQueueOverflow", 1,
     ("TcpListener: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: TcpListener downstream payload remove idle table"),
    ("tunnels/TlsClient/upstream/init.c", "tlsclientTunnelUpStreamInit", 1,
     ("TlsClient: unreachable",),
     "runtime flow-callback invariant: TlsClient upstream init unreachable branch"),
    ("tunnels/UdpConnector/upstream/fin.c", "udpconnectorTunnelUpStreamFinish", 1,
     ("UdpConnector: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: UdpConnector upstream fin remove idle table"),
    ("tunnels/UdpConnector/upstream/init.c", "udpconnectorTunnelUpStreamInit", 1,
     ("UdpConnector: internal DomainResolver prepare state is missing",),
     "runtime flow-callback invariant: UdpConnector upstream init missing domain resolver"),
    ("tunnels/UdpConnector/upstream/payload.c", "closeLine", 1,
     ("UdpConnector: failed to remove idle item for FD:%x",),
     "runtime flow-callback invariant: UdpConnector upstream payload remove idle table"),
    ("tunnels/UdpConnector/upstream/payload.c", "udpconnectorTunnelUpStreamPayload", 1,
     ("UdpConnector: UpStream Payload is called on closed wio. This should not happen",),
     "runtime flow-callback invariant: UdpConnector upstream payload closed wio"),
    ("tunnels/UdpListener/downstream/fin.c", "udplistenerTunnelDownStreamFinish", 1,
     ("UdpListener: Failed to remove idle item for UDP listener on FD:%x",),
     "runtime flow-callback invariant: UdpListener downstream fin remove idle table"),
    ("tunnels/UdpOverTcpClient/upstream/payload.c", "udpovertcpclientTunnelUpStreamPayload", 1,
     ("UdpOverTcpClient: Received empty payload, this is a bug, our eventloop logic dose not allow read of size",),
     "runtime flow-callback invariant: UdpOverTcpClient upstream payload empty event loop payload"),
    ("tunnels/UdpOverTcpServer/downstream/payload.c", "udpovertcpserverTunnelDownStreamPayload", 1,
     ("UdpOverTcpServer: Received empty payload, this is a bug, our eventloop logic dose not allow read of size",),
     "runtime flow-callback invariant: UdpOverTcpServer downstream payload empty event loop payload"),
    ("tunnels/AuthenticationServer/instance/chain.c", "authenticationserverTunnelOnChain", 1,
     ("AuthenticationServer: onChain override is disabled, use the default tunnel chaining",),
     "disabled lifecycle callback stub: AuthenticationServer onChain"),
    ("tunnels/Disturber/instance/chain.c", "disturberTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: Disturber onChain"),
    ("tunnels/EncryptionClient/instance/chain.c", "encryptionclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: EncryptionClient onChain"),
    ("tunnels/EncryptionServer/instance/chain.c", "encryptionserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: EncryptionServer onChain"),
    ("tunnels/HalfDuplexClient/instance/chain.c", "halfduplexclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: HalfDuplexClient onChain"),
    ("tunnels/HalfDuplexServer/instance/chain.c", "halfduplexserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: HalfDuplexServer onChain"),
    ("tunnels/HttpClient/instance/chain.c", "httpclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: HttpClient onChain"),
    ("tunnels/HttpServer/instance/chain.c", "httpserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: HttpServer onChain"),
    ("tunnels/IpOverrider/instance/chain.c", "ipoverriderOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: IpOverrider onChain"),
    ("tunnels/KeepAliveClient/instance/chain.c", "keepaliveclientTunnelOnChain", 1,
     ("KeepAliveClient: onChain override should not be used",),
     "disabled lifecycle callback stub: KeepAliveClient onChain"),
    ("tunnels/KeepAliveServer/instance/chain.c", "keepaliveserverTunnelOnChain", 1,
     ("KeepAliveServer: onChain override should not be used",),
     "disabled lifecycle callback stub: KeepAliveServer onChain"),
    ("tunnels/MuxClient/instance/chain.c", "muxclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: MuxClient onChain"),
    ("tunnels/MuxServer/instance/chain.c", "muxserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: MuxServer onChain"),
    ("tunnels/ObfuscatorClient/instance/chain.c", "obfuscatorclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: ObfuscatorClient onChain"),
    ("tunnels/ObfuscatorServer/instance/chain.c", "obfuscatorserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: ObfuscatorServer onChain"),
    ("tunnels/PacketsToStream/instance/chain.c", "packetstostreamTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: PacketsToStream onChain"),
    ("tunnels/PingClient/instance/chain.c", "pingclientOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: PingClient onChain"),
    ("tunnels/PingServer/instance/chain.c", "pingserverOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: PingServer onChain"),
    ("tunnels/ReverseClient/instance/chain.c", "reverseclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: ReverseClient onChain"),
    ("tunnels/ReverseServer/instance/chain.c", "reverseserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: ReverseServer onChain"),
    ("tunnels/StreamToPackets/instance/chain.c", "streamtopacketsTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: StreamToPackets onChain"),
    ("tunnels/TcpOverUdpClient/instance/chain.c", "tcpoverudpclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: TcpOverUdpClient onChain"),
    ("tunnels/TcpOverUdpServer/instance/chain.c", "tcpoverudpserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: TcpOverUdpServer onChain"),
    ("tunnels/TesterClient/instance/chain.c", "testerclientTunnelOnChain", 1,
     ("TesterClient: explicit onChain is disabled, use the default tunnel chaining",),
     "disabled lifecycle callback stub: TesterClient onChain"),
    ("tunnels/TesterServer/instance/chain.c", "testerserverTunnelOnChain", 1,
     ("TesterServer: explicit onChain is disabled, use the default tunnel chaining",),
     "disabled lifecycle callback stub: TesterServer onChain"),
    ("tunnels/TlsClient/instance/chain.c", "tlsclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: TlsClient onChain"),
    ("tunnels/UdpOverTcpClient/instance/chain.c", "udpovertcpclientTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: UdpOverTcpClient onChain"),
    ("tunnels/UdpOverTcpServer/instance/chain.c", "udpovertcpserverTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: UdpOverTcpServer onChain"),
    ("tunnels/template/instance/chain.c", "templateTunnelOnChain", 1,
     ("This Function is disabled, using the default Tunnel instead",),
     "disabled lifecycle callback stub: template onChain"),
    ("tunnels/WireGuardDevice/instance/index.c", "wireguarddeviceTunnelOnIndex", 1,
     ("This Function is disabled, using the default PacketTunnel instead",),
     "disabled lifecycle callback stub: WireGuardDevice onIndex"),
    ("tunnels/AuthenticationClient/common/protocol.c", "authenticationclientOpenControlLine", 1,
     ("AuthenticationClient: control line must be opened on worker 0",),
     "helper/line-state invariant: AuthClient protocol worker not 0"),
    ("tunnels/AuthenticationClient/common/users_api.c", "authenticationclientAssertProfileEmpty", 1,
     ("AuthenticationClient: %s received a non-empty user profile output; clear it before reuse",),
     "helper/line-state invariant: AuthClient users_api profile contract"),
    ("tunnels/IpManipulator/common/tricks/smugglefin/trick.c", "smugglefintrickFlushQueuedPackets", 1,
     ("IpManipulator: worker packet line died while replaying smuggle-fin queued packets",),
     "helper/line-state invariant: IpManipulator trick packet line died 1"),
    ("tunnels/IpManipulator/common/tricks/smugglefin/trick.c", "smugglefintrickUpStreamPayload", 1,
     ("IpManipulator: worker packet line died during smuggle-fin send",),
     "helper/line-state invariant: IpManipulator trick packet line died 2"),
    ("tunnels/MuxClient/common/line_state.c", "muxclientLinestateDestroy", 4,
     ("MuxClient: Trying to destroy parent line state with %u children still attached",
      "MuxClient: Trying to destroy parent line state with child links still present",
      "MuxClient: Trying to destroy child line state while still linked to parent",
      "MuxClient: Trying to destroy child line state while still linked to siblings"),
     "helper/line-state invariant: MuxClient line-state parent/child/sibling link integrity"),
    ("tunnels/MuxServer/common/line_state.c", "muxserverLinestateDestroy", 4,
     ("MuxServer: Trying to destroy parent line state with %u children still attached",
      "MuxServer: Trying to destroy parent line state with child links still present",
      "MuxServer: Trying to destroy child line state while still linked to parent",
      "MuxServer: Trying to destroy child line state while still linked to siblings"),
     "helper/line-state invariant: MuxServer line-state parent/child/sibling link integrity"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderGetSingleProtocolNumber", 1,
     ("PacketSender: internal error, invalid single-protocol mode %u",),
     "helper/line-state invariant: PacketSender helpers default enum"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderResolveSourceAddress", 1,
     ("PacketSender: internal error, source index %llu is out of range",),
     "helper/line-state invariant: PacketSender helpers computed index range"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderSendReadyPackets", 1,
     ("PacketSender: worker packet line died during payload send",),
     "helper/line-state invariant: PacketSender helpers packet line died 1"),
    ("tunnels/PacketSender/common/helpers.c", "packetsenderStartWorker", 1,
     ("PacketSender: worker %u packet line is not available",),
     "helper/line-state invariant: PacketSender helpers packet line died 2"),
    ("tunnels/PacketsToConnection/common/netif.c", "ptcEmitPacketBufferAdmitted", 1,
     ("PacketsToConnection: packet line died during runtime, packet tunnel contract was violated",),
     "helper/line-state invariant: PacketsToConn admitted packet publication line died"),
    ("tunnels/TcpConnector/common/helpers.c", "tcpconnectorOnClose", 1,
     ("TcpConnector: failed to remove idle item for FD:%x",),
     "helper/line-state invariant: TcpConnector helpers remove idle table"),
    ("tunnels/TcpConnector/common/line_state.c", "tcpconnectorLinestateDestroy", 1,
     ("TcpConnector: idle item still exists for FD:%x",),
     "helper/line-state invariant: TcpConnector line_state live idle entry"),
    ("tunnels/TcpListener/common/helpers.c", "onClose", 1,
     ("TcpListener: failed to remove idle item for FD:%x",),
     "helper/line-state invariant: TcpListener helpers remove idle table"),
    ("tunnels/TcpListener/common/line_state.c", "tcplistenerLinestateDestroy", 1,
     ("TcpListener: idle item still exists for FD:%x",),
     "helper/line-state invariant: TcpListener line_state live idle entry"),
    ("tunnels/TcpUdpConnector/common/helpers.c", "tcpudpconnectorGetSelectedUpStreamTunnel", 1,
     ("TcpUdpConnector: upstream callback received before init selected a connector",),
     "helper/line-state invariant: TcpUdpConnector helpers internal connector"),
    ("tunnels/TcpUdpListener/common/helpers.c", "tcpudplistenerSelectDownStreamTunnel", 1,
     ("TcpUdpListener: line has ambiguous or missing source protocol flags (tcp=%u, udp=%u)",),
     "helper/line-state invariant: TcpUdpListener helpers protocol flags"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverResponseSendTask", 2,
     ("TesterServer: packet line died during packet-mode response send",
      "TesterServer: large buffer pool reports zero writable payload capacity"),
     "helper/line-state invariant: TesterServer helpers packet line died and zero writable capacity"),
    ("tunnels/UdpConnector/common/helpers.c", "udpconnectorOnClose", 1,
     ("UdpConnector: failed to remove idle item for FD:%x",),
     "helper/line-state invariant: UdpConnector helpers remove idle table"),
    ("tunnels/UdpConnector/common/line_state.c", "udpconnectorLinestateDestroy", 1,
     ("UdpConnector: idle item still exists for FD:%x",),
     "helper/line-state invariant: UdpConnector line_state live idle entry"),
    ("tunnels/UdpStatelessSocket/common/helpers.c", "udpstatelesssocketCloseOwnedLineFromAdjacent", 1,
     ("UdpStatelessSocket: failed to remove idle item for peer line",),
     "helper/line-state invariant: UdpStatelessSocket helpers worker idle entry"),
    ("tunnels/UdpStatelessSocket/common/line_state.c", "udpstatelesssocketLinestateDestroy", 1,
     ("UdpStatelessSocket: idle item still exists while destroying peer line state",),
     "helper/line-state invariant: UdpStatelessSocket line_state live idle entry"),
    ("tunnels/AuthenticationClient/instance/start.c", "authenticationclientStartOnWorker0", 1,
     ("AuthenticationClient: startup control task ran on worker %u",),
     "worker-task invariant: AuthClient start worker 0"),
    ("tunnels/TesterClient/instance/start.c", "testerclientStartWorker", 1,
     ("TesterClient: packet line died during packet-mode init",),
     "worker-task invariant: TesterClient start packet line died"),
    ("tunnels/WireGuardDevice/instance/start.c", "wireguarddeviceQueueWorkerPacketInit", 1,
     ("WireGuardDevice: worker packet line died during packet-side init",),
     "worker-task invariant: WireGuardDevice start packet line died"),
    ("tunnels/TcpOverUdpClient/common/line_state.c", "tcpoverudpclientLinestateInitialize", 1,
     ("TcpOverUdpClient: KCP rejected the validated MTU %d (result %d)",),
     "per-line initialization invariant: TcpOverUdpClient impossible MTU rejection"),
    ("tunnels/TcpOverUdpServer/common/line_state.c", "tcpoverudpserverLinestateInitialize", 1,
     ("TcpOverUdpServer: KCP rejected the validated MTU %d (result %d)",),
     "per-line initialization invariant: TcpOverUdpServer impossible MTU rejection"),
    ("tunnels/Router/common/geoip.c", "routerGeoipLookupCountry", 1,
     ("Router: GeoIP rule evaluated without an open MaxMind database",),
     "per-request evaluation invariant: Router GeoIP database was never opened"),
    ("tunnels/Internals/DomainResolver/instance/api.c", "domainresolverTunnelSetPrepareHook", 4,
     ("DomainResolver: prepare hook must be configured before chaining",
      "DomainResolver: prepare hook line state is too large",
      "DomainResolver: internal line state is too large"),
     "internal API / unsafe destruction: DomainResolver prepare-hook order and line-state arithmetic"),
    ("tunnels/UdpStatelessSocket/instance/destroy.c", "udpstatelesssocketTunnelDestroy", 1,
     ("UdpStatelessSocket: destroying with active worker-local idle table for worker %u",),
     "internal API / unsafe destruction: UdpStatelessSocket destroy active idle tables"),
    # ------------------------------------------------------------------
    # Tester internal invariants. A failed integrity test is a runtime verdict
    # that requests an orderly shutdown (see EXCLUSIONS), but a payload
    # generator asked for an impossible payload, a pool with no writable
    # capacity, a close scheduled before verification and a Finish on a
    # persistent worker packet line are all broken internal state. They must
    # hard-abort and must never reach the orderly verdict helper.
    # ------------------------------------------------------------------
    ("tunnels/TesterClient/common/helpers.c", "testerclientCreatePayload", 4,
     ("TesterClient: packet-mode payload generation attempted to split a packet chunk",
      "TesterClient: packet-mode requires enough small-buffer capacity for the maximum packet length",
      "TesterClient: stream-mode payload generation exceeded large buffer size",
      "TesterClient: packet-ipv4 chunk size is smaller than the configured packet headers"),
     "tester invariant: TesterClient impossible payload-generator states"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientRequestSendTask", 1,
     ("TesterClient: large buffer pool reports zero writable payload capacity",),
     "tester invariant: TesterClient zero writable large-buffer capacity"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientCloseCompletedStreamTask", 1,
     ("TesterClient: scheduled close before response verification completed",),
     "tester invariant: TesterClient close scheduled before verification"),
    ("tunnels/TesterClient/downstream/payload.c", "testerclientTunnelDownStreamPayloadStateless", 1,
     ("TesterClient: packet-mode stateless response count reached completion with missing chunks",),
     "tester invariant: TesterClient stateless response count/mask disagreement"),
    ("tunnels/TesterClient/downstream/fin.c", "testerclientTunnelDownStreamFinish", 1,
     ("TesterClient: packet-mode received unexpected finish on worker packet line",),
     "tester invariant: TesterClient Finish on a persistent packet line"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverCreatePayload", 4,
     ("TesterServer: packet-mode payload generation attempted to split a packet chunk",
      "TesterServer: packet-mode response exceeded small buffer size",
      "TesterServer: stream-mode payload generation exceeded large buffer size",
      "TesterServer: packet-ipv4 chunk size is smaller than the configured packet headers"),
     "tester invariant: TesterServer impossible payload-generator states"),
    ("tunnels/TesterServer/upstream/fin.c", "testerserverTunnelUpStreamFinish", 1,
     ("TesterServer: packet-mode received unexpected finish on worker packet line",),
     "tester invariant: TesterServer Finish on a persistent packet line"),
    ("tunnels/TesterServer/downstream/fin.c", "testerserverTunnelDownStreamFinish", 2,
     ("TesterServer: packet-mode received unexpected downstream finish on worker packet line",
      "TesterServer: downStreamFinish disabled"),
     "tester invariant: TesterServer packet-line Finish and disabled stream-mode callback"),
    # ------------------------------------------------------------------
    # Worker-dispatch packet-line invariant outside tunnels/. A persistent
    # worker packet line is process-lifetime state, so its death during chain
    # initialization invalidates the assumptions orderly teardown relies on.
    # ------------------------------------------------------------------
    ("ww/managers/node_manager.c", "nodemanagerInitializeLineOnTargetWorker", 1,
     ("NodeManager: node startup failure: line initialization failed for node (\\\"%s\\\") on worker %d",),
     "worker-task invariant: NodeManager persistent packet line died during chain init"),
]


# Function-level exclusions. These are call sites that must NOT become
# Category-D hard aborts. Each entry pins the intended termination policy in one
# exact function, so an unrelated process-control call elsewhere in the same
# file can no longer satisfy the check.
#
#   (relative path, function name, {call name: expected count}, anchors, why)
#
# The legacy terminateProgram() spelling remains a zero-call check for audited
# Category-C functions so it cannot be reintroduced unnoticed.

EXCLUSIONS = [
    ("tunnels/TesterClient/common/helpers.c", "testerclientFail",
     {"terminateProgram": 0, "abortProgramNow": 1, "requestProgramShutdown": 1},
     ("TesterClient: worker %u failed: %s",),
     "orderly runtime shutdown request from an arbitrary worker"),
    ("tunnels/TesterServer/common/helpers.c", "testerserverFail",
     {"terminateProgram": 0, "abortProgramNow": 1, "requestProgramShutdown": 1},
     ("TesterServer: worker %u failed: %s",),
     "orderly runtime shutdown request from an arbitrary worker"),
    ("tunnels/TesterClient/common/helpers.c", "testerclientRequestSuccessfulShutdown",
     {"terminateProgram": 0, "abortProgramNow": 1, "requestProgramShutdown": 1},
     ("TesterClient: all %u worker lines completed successfully",),
     "Category-A successful completion, isolated from every invariant abort"),
    # ------------------------------------------------------------------
    # Category-C: one line or one request failed. These functions must not
    # terminate, abort, or request a shutdown of the process; they clean up and
    # close only the affected line. Every one of them is pinned at zero calls to
    # all three process APIs.
    # ------------------------------------------------------------------
    # The per-tunnel Mux encoders were consolidated into MuxCommon, and the
    # "closing this child" verdict now lives in the two callers, so the encoder
    # and both callers are pinned where the code actually is.
    ("tunnels/Internals/MuxCommon/src/mux_wire.c", "muxEncodeChildPayload",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     (),
     "Category-C: oversized valid Mux payload is fragmented, never fatal"),
    ("tunnels/Internals/MuxCommon/src/mux_wire.c", "muxMakeMuxFrame",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     (),
     "Category-C: Mux frame encoder must not police payload size fatally"),
    ("tunnels/MuxClient/upstream/payload.c", "muxclientTunnelUpStreamPayload",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("MuxClient: cid %u payload of %u bytes cannot be encoded into MUX frames, closing this child",),
     "Category-C: oversized valid MuxClient payload closes one child only"),
    ("tunnels/MuxServer/downstream/payload.c", "muxserverTunnelDownStreamPayload",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("MuxServer: cid %u payload of %u bytes cannot be encoded into MUX frames, closing this child",),
     "Category-C: oversized valid MuxServer payload closes one child only"),
    ("tunnels/TlsClient/common/line_state.c", "tlsclientLinestateInitializeWithShaping",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("Failed to allocate TlsClient BoringSSL line state",),
     "Category-C: TlsClient per-line BoringSSL allocation failure closes one line"),
    ("tunnels/TlsServer/common/helpers.c", "tlsserverArmHandshakeDeadline",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("TlsServer: failed to create the TLS handshake deadline timer for this line",),
     "Category-C: TlsServer per-line timer allocation failure closes one line"),
    ("tunnels/SpeedLimit/common/helpers.c", "speedlimitScheduleUpstreamDrain",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("SpeedLimit: failed to create the upstream drain timer for this line",),
     "Category-C: SpeedLimit per-line timer allocation failure closes one line"),
    ("tunnels/SpeedLimit/common/helpers.c", "speedlimitScheduleDownstreamDrain",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("SpeedLimit: failed to create the downstream drain timer for this line",),
     "Category-C: SpeedLimit per-line timer allocation failure closes one line"),
    ("tunnels/TcpUdpConnector/common/helpers.c", "tcpudpconnectorSelectUpStreamTunnel",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("TcpUdpConnector: line has no TCP/UDP protocol flags in destination or source context",),
     "Category-C: TcpUdpConnector rejects one line instead of terminating"),
    ("tunnels/Router/common/geoip.c", "routerGeoipReadIsoCode",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     ("Router: MaxMind lookup failed at %s.iso_code: %s",
      "Router: MaxMind %s.iso_code is not a two-letter string"),
     "Category-C: Router MaxMind read errors propagate as evaluation failures"),
    ("tunnels/Router/common/geosite_db.c", "geositeRegexPatternsMatch",
     {"terminateProgram": 0, "abortProgramNow": 0, "requestProgramShutdown": 0},
     (r'Router: GeoSite regex matcher failed at runtime for list \"%s\" (STC cregex error %d)',),
     "Category-C: peer-reachable regex failure must never be a process-kill primitive"),
]


# A candidate function may only keep a non-Category-D termination call when the
# audit deliberately left it there. Every such call is listed here with its
# exact expected count; every other candidate function must have none.
#
# This is currently empty: authenticationclientStartOnWorker0() used to retain a
# ping-timer terminateProgram(), but that timer failure is a Category-B runtime
# failure and now lives in authenticationclientStartPingTimer(), which
# tests/tunnels_orderly_shutdown_policy_test.py pins.
RETAINED_NON_ABORT_CALLS = {}


# Removals the previous line-proximity checker silently accepted. They are
# re-exercised by name so the regression cannot come back unnoticed.
MANDATORY_REGRESSION_MUTATIONS = [
    ("tunnels/ReverseClient/common/helpers.c", "reverseclientClosePair"),
    ("tunnels/MuxClient/common/line_state.c", "muxclientLinestateDestroy"),
    ("tunnels/MuxServer/common/line_state.c", "muxserverLinestateDestroy"),
    ("tunnels/Internals/DomainResolver/instance/api.c", "domainresolverTunnelSetPrepareHook"),
]


# ---------------------------------------------------------------------------
# Source access and analysis caches
# ---------------------------------------------------------------------------

_FILE_CACHE = {}
_ANALYSIS_CACHE = {}


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


def analyze(content):
    """Return (masked_source, {function name: [body span, ...]}) for content."""
    cached = _ANALYSIS_CACHE.get(content)
    if cached is None:
        masked = mask_source(content)
        cached = (masked, find_function_definitions(masked))
        _ANALYSIS_CACHE[content] = cached
    return cached


def resolve_function(content, rel_path, function, label, errors):
    """Return the single body span of ``function``, or None after reporting."""
    masked, definitions = analyze(content)
    spans = definitions.get(function, [])
    if not spans:
        errors.append("[%s] %s: no definition of %s()" % (label, rel_path, function))
        return None
    if len(spans) > 1:
        lines = [line_of(content, span[0]) for span in spans]
        errors.append(
            "[%s] %s: %s() is defined %d times (lines %s); a candidate must name exactly one function"
            % (label, rel_path, function, len(spans), lines)
        )
        return None
    return spans[0]


def count_calls(masked, span, call_name):
    return len(_CALL_PATTERNS[call_name].findall(masked, span[0], span[1]))


# ---------------------------------------------------------------------------
# Policy verification
# ---------------------------------------------------------------------------

def verify_policy(source_overrides=None):
    errors = []
    checked_functions = 0
    checked_aborts = 0

    expected_total = sum(entry[2] for entry in MANIFEST)
    if expected_total != EXPECTED_TOTAL_ABORTS:
        errors.append(
            "Manifest accounts for %d aborts, expected exactly %d"
            % (expected_total, EXPECTED_TOTAL_ABORTS)
        )

    seen_keys = set()
    for rel_path, function, expected, anchors, description in MANIFEST:
        key = (rel_path, function)
        if key in seen_keys:
            errors.append("Duplicate manifest entry for %s::%s" % (rel_path, function))
            continue
        seen_keys.add(key)

        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[%s] Candidate file missing: %s" % (description, rel_path))
            continue

        span = resolve_function(content, rel_path, function, description, errors)
        if span is None:
            continue

        checked_functions += 1
        checked_aborts += expected

        masked, _ = analyze(content)
        body_masked = masked[span[0]:span[1]]
        body_source = content[span[0]:span[1]]
        body_line = line_of(content, span[0])

        total_aborts = len(_ABORT_ANY_RE.findall(body_masked))
        hard_aborts = len(_ABORT_HARD_RE.findall(body_masked))

        if hard_aborts != expected:
            errors.append(
                "[%s] %s::%s (line %d) has %d abortProgramNow(1); call(s), expected %d"
                % (description, rel_path, function, body_line, hard_aborts, expected)
            )
        if total_aborts != hard_aborts:
            errors.append(
                "[%s] %s::%s (line %d) has %d abortProgramNow() call(s) but only %d use exit code 1"
                % (description, rel_path, function, body_line, total_aborts, hard_aborts)
            )

        retained = RETAINED_NON_ABORT_CALLS.get(key, {})

        expected_terminate = retained.get("terminateProgram", 0)
        reintroduced = count_calls(masked, span, "terminateProgram")
        if reintroduced != expected_terminate:
            errors.append(
                "[%s] %s::%s (line %d) has %d terminateProgram() call(s), expected %d"
                % (description, rel_path, function, body_line, reintroduced, expected_terminate)
            )

        expected_request = retained.get("requestProgramShutdown", 0)
        requested = count_calls(masked, span, "requestProgramShutdown")
        if requested != expected_request:
            errors.append(
                "[%s] %s::%s (line %d) has %d requestProgramShutdown() call(s), expected %d; "
                "this site must abort immediately"
                % (description, rel_path, function, body_line, requested, expected_request)
            )

        for anchor in anchors:
            if anchor not in body_source:
                errors.append(
                    "[%s] %s::%s (line %d) lost the invariant diagnostic %r"
                    % (description, rel_path, function, body_line, anchor)
                )

    for rel_path, function, expected_calls, anchors, reason in EXCLUSIONS:
        content = read_source(rel_path, source_overrides)
        if content is None:
            errors.append("[exclusion: %s] Excluded file missing: %s" % (reason, rel_path))
            continue

        label = "exclusion: %s" % reason
        span = resolve_function(content, rel_path, function, label, errors)
        if span is None:
            continue

        masked, _ = analyze(content)
        body_source = content[span[0]:span[1]]
        body_line = line_of(content, span[0])

        for call_name, expected_count in sorted(expected_calls.items()):
            actual = count_calls(masked, span, call_name)
            if actual != expected_count:
                errors.append(
                    "[%s] %s::%s (line %d) has %d %s() call(s), expected %d"
                    % (label, rel_path, function, body_line, actual, call_name, expected_count)
                )

        for anchor in anchors:
            if anchor not in body_source:
                errors.append(
                    "[%s] %s::%s (line %d) lost the diagnostic %r"
                    % (label, rel_path, function, body_line, anchor)
                )

    return errors, checked_functions, checked_aborts


# ---------------------------------------------------------------------------
# Mutation testing
# ---------------------------------------------------------------------------

def abort_call_spans(content, function):
    masked, definitions = analyze(content)
    span = definitions[function][0]
    return [match.span() for match in _ABORT_HARD_RE.finditer(masked, span[0], span[1])]


def mutate_abort(content, function, index, replacement):
    start, end = abort_call_spans(content, function)[index]
    return content[:start] + replacement + content[end:]


def mutate_exclusion_to_hard_abort(content, function, call_name):
    masked, definitions = analyze(content)
    span = definitions[function][0]
    match = _CALL_PATTERNS[call_name].search(masked, span[0], span[1])
    start = match.start()
    return content[:start] + "abortProgramNow" + content[start + len(call_name):]


def mutate_insert_call(content, function, snippet):
    """Insert ``snippet`` right after the opening brace of ``function``'s body."""
    _masked, definitions = analyze(content)
    body_start = definitions[function][0][0]
    insert_at = body_start + 1
    return content[:insert_at] + "\n    " + snippet + content[insert_at:]


class MutationRunner:
    def __init__(self):
        self.applied = 0
        self.escaped = []

    def expect_failure(self, label, rel_path, mutated):
        self.applied += 1
        errors, _, _ = verify_policy({rel_path: mutated})
        if not errors:
            self.escaped.append(label)
            return False
        return True


def run_mutation_tests():
    print("Running mutation tests on the policy checker...")
    runner = MutationRunner()

    replacements = [
        ("terminateProgram", "terminateProgram(1);"),
        ("requestProgramShutdown", "requestProgramShutdown(1);"),
        ("exit code 0", "abortProgramNow(0);"),
        ("commented out", "// abortProgramNow(1);"),
        ("string literal", '(void) "abortProgramNow(1);";'),
        ("declaration only", "void abortProgramNow(int);"),
    ]

    covered_regressions = set()

    for rel_path, function, expected, _anchors, _description in MANIFEST:
        content = read_source(rel_path, None)
        spans = abort_call_spans(content, function)
        if len(spans) != expected:
            runner.escaped.append(
                "%s::%s: found %d mutable abort call(s), manifest expects %d"
                % (rel_path, function, len(spans), expected)
            )
            continue

        # 1 & 2: every required abort must be individually load-bearing.
        for index in range(expected):
            label = "%s::%s remove abort #%d" % (rel_path, function, index + 1)
            runner.expect_failure(label, rel_path, mutate_abort(content, function, index, ""))

        # 3 - 6: lookalikes must never satisfy a candidate.
        for name, replacement in replacements:
            label = "%s::%s abort #1 -> %s" % (rel_path, function, name)
            runner.expect_failure(
                label, rel_path, mutate_abort(content, function, 0, replacement)
            )

        if (rel_path, function) in MANDATORY_REGRESSION_MUTATIONS:
            covered_regressions.add((rel_path, function))

    # Deliberately retained non-Category-D calls must not drift either.
    for (rel_path, function), retained in sorted(RETAINED_NON_ABORT_CALLS.items()):
        content = read_source(rel_path, None)
        for call_name in sorted(retained):
            label = "retained %s::%s %s() -> abortProgramNow()" % (rel_path, function, call_name)
            runner.expect_failure(
                label, rel_path, mutate_exclusion_to_hard_abort(content, function, call_name)
            )

    # 7: exclusions must not drift toward a Category-D hard abort.
    for rel_path, function, expected_calls, _anchors, reason in EXCLUSIONS:
        content = read_source(rel_path, None)
        for call_name, expected_count in sorted(expected_calls.items()):
            if call_name == "abortProgramNow" or expected_count == 0:
                continue
            label = "exclusion %s::%s %s() -> abortProgramNow()" % (rel_path, function, call_name)
            runner.expect_failure(
                label, rel_path, mutate_exclusion_to_hard_abort(content, function, call_name)
            )

    # 8: a Category-C function pinned at zero calls must reject every process API that is
    #    smuggled back into it. Removing a call cannot be mutated there, so the inverse is
    #    exercised instead: inject one and require the checker to catch it.
    for rel_path, function, expected_calls, _anchors, reason in EXCLUSIONS:
        content = read_source(rel_path, None)
        for call_name, expected_count in sorted(expected_calls.items()):
            if expected_count != 0:
                continue
            snippet = "%s(1);" % call_name
            label = "exclusion %s::%s gained %s" % (rel_path, function, snippet)
            runner.expect_failure(
                label, rel_path, mutate_insert_call(content, function, snippet)
            )

    missing_regressions = [
        entry for entry in MANDATORY_REGRESSION_MUTATIONS if entry not in covered_regressions
    ]
    for rel_path, function in missing_regressions:
        runner.escaped.append(
            "mandatory regression mutation never ran for %s::%s" % (rel_path, function)
        )

    if runner.escaped:
        print("Mutation testing FAILED: %d mutation(s) were not detected:" % len(runner.escaped))
        for label in runner.escaped:
            print("  - %s" % label)
        return False

    print(
        "  %d mutations applied, all detected (including the %d previously missed removals)."
        % (runner.applied, sum(entry[2] for entry in MANIFEST if (entry[0], entry[1]) in MANDATORY_REGRESSION_MUTATIONS))
    )
    return True


def main():
    errors, checked_functions, checked_aborts = verify_policy()

    if errors:
        print("Policy Check FAILED with %d error(s):" % len(errors))
        for error in errors:
            print("  - %s" % error)
        sys.exit(1)

    print(
        "Policy Check PASSED: %d Category-D abortProgramNow(1) call(s) across %d function(s), "
        "%d function-level exclusion(s) intact."
        % (checked_aborts, checked_functions, len(EXCLUSIONS))
    )

    if "--mutation-test" in sys.argv or "-m" in sys.argv:
        if not run_mutation_tests():
            sys.exit(1)


if __name__ == "__main__":
    main()
