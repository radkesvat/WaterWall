"""Positive strace calls, including interleaved unfinished/resumed records."""
import re


def successful_calls(trace):
    """Join strace's per-thread resumed calls before checking socket endpoints."""
    pending = {}
    for line in trace.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        tid, call = match.groups()
        if call.endswith("<unfinished ...>"):
            pending[tid] = call.removesuffix("<unfinished ...>")
            continue
        resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", call)
        if resumed:
            call = pending.pop(tid, "") + resumed.group(1)
        if re.search(r"\)\s+= [1-9]\d*", call):
            yield call


def positive_splice_counts(trace):
    """Counts from complete/resumed splice lines used by Trojan/VLESS fixtures."""
    return re.findall(r"(?:splice\(.*|<\.\.\. splice resumed>.*)\s= ([1-9][0-9]*)", trace)
