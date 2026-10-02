"""Lexical C analysis shared by the source-policy programs. Masks preserve every offset/newline.
Callers keep their manifests and mutation verdicts; this module never decides a policy or changes
source files."""
import re
from pathlib import Path

ROOT = str(Path(__file__).resolve().parents[4])
_ANALYSIS_CACHE = {}


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


_CALL_PATTERNS = {
    "abortProgramNow": _call_re("abortProgramNow"),
    "terminateProgram": _call_re("terminateProgram"),
    "requestProgramShutdown": _call_re("requestProgramShutdown"),
    "quiescenceGateAbortUnderflow": _call_re("quiescenceGateAbortUnderflow"),
}


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
