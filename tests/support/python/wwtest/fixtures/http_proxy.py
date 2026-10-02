"""HTTP wire observations for the shared 27971/27972 loopback proxy fixture. Read limit, positive
syscall gate and exact up/down endpoint mapping are fixed; scenario assertions and IPv6
normalization remain at each caller."""
import re
from ..sockets import exact
from ..trace import successful_calls


def header(sock):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        assert len(result) <= 65536, "oversized HTTP header"
    return bytes(result)


def splice_outputs(trace):
    outputs = set()
    positive = False
    for call in successful_calls(trace):
        if not call.startswith("splice("):
            continue
        positive = True
        match = re.match(r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:\[([^]]+)\]>, NULL,", call)
        if match:
            endpoints = match.group(1)
            if endpoints.endswith("->127.0.0.1:27972"):
                outputs.add("up")
            if endpoints.startswith("127.0.0.1:27971->"):
                outputs.add("down")
    return positive, outputs
