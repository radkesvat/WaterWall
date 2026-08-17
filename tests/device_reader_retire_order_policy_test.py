#!/usr/bin/env python3
"""Every platform lifecycle wrapper must close, then join, then retire the pool.

R12-02. The reader-session end request closes admission without waiting. Its wait
phase quiesces delivery before poisoning the fragment generation, but deliberately
leaves staged reader buffers alone while the reader thread still owns the
thread-affine reader pool.

The buffers are retired instead once the producer has joined and the pool's
thread ownership has been reset. That ordering is a property of every platform's
bring-down and rollback path, not of one of them, so it is checked as source
policy rather than left to whichever platform happens to have a runtime test.
"""

from pathlib import Path
import re


root = Path(__file__).resolve().parents[1]

# Each file must reset the reader pool's ownership and retire the generation's
# buffers together, in that order, at every point where the reader was joined.
sources = (
    "ww/devices/capture/capture_linux.c",
    "ww/devices/capture/capture_windows.c",
    "ww/devices/tun/tun_linux.c",
    "ww/devices/tun/tun_darwin.c",
    "ww/devices/tun/tun_windows.c",
)

reset_pattern = re.compile(r"bufferpoolResetThreadOwnership\((\w+)->reader_buffer_pool\);")
retire_pattern = re.compile(r"deviceReaderSessionRetireGenerationBuffers\((\w+)->reader_session\);")

for relative in sources:
    text = (root / relative).read_text(encoding="utf-8")

    resets = list(reset_pattern.finditer(text))
    retires = list(retire_pattern.finditer(text))
    if not resets:
        raise SystemExit(f"{relative}: no reader-pool ownership reset after the producer join")
    if len(resets) != len(retires):
        raise SystemExit(
            f"{relative}: {len(resets)} reader-pool ownership reset(s) but {len(retires)} generation retire(s)"
        )

    for reset, retire in zip(resets, retires):
        if retire.start() < reset.end():
            raise SystemExit(f"{relative}: staged reader buffers are retired before the pool ownership is reset")
        between = text[reset.end():retire.start()]
        if between.strip():
            raise SystemExit(f"{relative}: the generation retire does not immediately follow the ownership reset")

    # End must never be the thing that returns buffers to a live reader pool.
    end_call = "deviceReaderSessionEnd("
    for match in re.finditer(re.escape(end_call), text):
        tail = text[match.end():match.end() + 400]
        if "RetireGenerationBuffers" in tail.split(";")[0]:
            raise SystemExit(f"{relative}: End retires producer buffers on the lifecycle thread")

end_source = (root / "ww/devices/device_reader_session.c").read_text(encoding="utf-8")
end_body = end_source[end_source.index("void deviceReaderSessionEnd("):]
end_body = end_body[: end_body.index("\n}\n") + 2]
if not end_body.index("deviceReaderSessionEndRequest") < end_body.index("deviceReaderSessionEndWait"):
    raise SystemExit("deviceReaderSessionEnd() no longer requests closure before waiting")

wait_body = end_source[end_source.index("void deviceReaderSessionEndWait("):]
wait_body = wait_body[: wait_body.index("\n}\n") + 2]
if "deviceFragAffinityEndGeneration" not in wait_body:
    raise SystemExit("deviceReaderSessionEndWait() no longer closes the fragment generation")
if "RetireGenerationBuffers" in wait_body or "ReleaseStagedBuffers" in wait_body:
    raise SystemExit("deviceReaderSessionEndWait() returns staged buffers while the reader may still own the pool")
if wait_body.index("deviceFragAffinityEndGeneration") < wait_body.index("quiescenceGateWaitQuiesced"):
    raise SystemExit("deviceReaderSessionEndWait() closes fragment classification before in-flight receipts quiesce")

print("all device lifecycle wrappers close, join, then retire the reader generation's buffers")
