#!/usr/bin/env python3
"""Bounded TCP-carrier progress/scale probe; runs inside the namespace harness."""
import asyncio
import json
import os
from pathlib import Path
import re
import resource
import struct
import subprocess
import time

HEADER = struct.Struct("!cIII")
DURATION = float(os.getenv("MUX_PRESSURE_SECONDS", "7"))
CHILDREN = int(os.getenv("MUX_PRESSURE_CHILDREN", "12"))
HOT = int(os.getenv("MUX_PRESSURE_HOT", "4"))
BATCH = int(os.getenv("MUX_PRESSURE_BATCH", "1048576"))
DIRECTION = os.getenv("MUX_PRESSURE_DIRECTION", "both")
NETEM = os.getenv("MUX_PRESSURE_NETEM", "false") == "true"
COUNTS = {"upload_sent": 0, "upload_received": 0, "download_sent": 0, "download_received": 0, "exchanges": 0, "churn": 0}
ERRORS = []
HANDLERS = set()
WRITERS = set()
RUNTIME_PID = None
MAX_RSS_KIB = 0
MAX_FDS = 0


def payload(cid, sequence, length):
    tag = struct.pack("!II", cid, sequence)
    return (tag * ((length + 7) // 8))[:length]


async def destination(reader, writer):
    task = asyncio.current_task()
    HANDLERS.add(task)
    WRITERS.add(writer)
    try:
        while True:
            mode, cid, sequence, length = HEADER.unpack(await reader.readexactly(HEADER.size))
            expected = payload(cid, sequence, length)
            if mode == b"D":
                writer.write(expected)
                await writer.drain()
                COUNTS["download_sent"] += length
            else:
                # A bounded destination stall; other streams keep running.
                if mode == b"U" and sequence == 1:
                    await asyncio.sleep(0.5)
                received = await reader.readexactly(length)
                if received != expected:
                    raise AssertionError(f"upload FIFO corruption cid={cid} sequence={sequence}")
                if mode == b"U":
                    COUNTS["upload_received"] += length
                writer.write(expected if mode == b"E" else b"K")
                await writer.drain()
    except asyncio.IncompleteReadError as exc:
        if exc.partial:
            ERRORS.append(f"partial destination frame: {len(exc.partial)} bytes")
    except (ConnectionError, AssertionError) as exc:
        ERRORS.append(str(exc))
    finally:
        writer.close()
        await writer.wait_closed()
        WRITERS.discard(writer)
        HANDLERS.discard(task)


async def connect():
    for _ in range(100):
        try:
            return await asyncio.open_connection("127.0.0.1", 26880)
        except ConnectionRefusedError:
            await asyncio.sleep(0.05)
    raise AssertionError("source listener unavailable")


async def child(cid, ready, start):
    reader, writer = await connect()
    mode = b"E"
    if cid < HOT:
        mode = b"U" if DIRECTION == "upload" else b"D" if DIRECTION == "download" else (b"U" if cid % 2 == 0 else b"D")
    sequence = 0
    try:
        # Prompt useful traffic avoids the initial idle timeout during scale setup.
        hello = payload(cid, sequence, 16)
        writer.write(HEADER.pack(b"E", cid, sequence, 16) + hello)
        await writer.drain()
        assert await reader.readexactly(16) == hello
        ready[cid] = True
        await start.wait()
        deadline = time.monotonic() + DURATION
        while time.monotonic() < deadline:
            sequence += 1
            length = BATCH if mode != b"E" else 32
            expected = payload(cid, sequence, length)
            writer.write(HEADER.pack(mode, cid, sequence, length))
            if mode != b"D":
                writer.write(expected)
            await writer.drain()
            if mode == b"U":
                COUNTS["upload_sent"] += length
            if mode == b"D" and sequence == 1:
                await asyncio.sleep(0.5)
            result = await asyncio.wait_for(reader.readexactly(1 if mode == b"U" else length), 90)
            assert result == (b"K" if mode == b"U" else expected), f"download FIFO corruption cid={cid} sequence={sequence}"
            if mode == b"D":
                COUNTS["download_received"] += length
            COUNTS["exchanges"] += 1
            if mode == b"E":
                # Bounded churn preserves a mostly stable population and the same parent.
                if cid % 100 == 4 and sequence % 4 == 0:
                    writer.close()
                    await writer.wait_closed()
                    reader, writer = await connect()
                    writer.write(HEADER.pack(b"E", cid, sequence, 16) + payload(cid, sequence, 16))
                    await writer.drain()
                    assert await reader.readexactly(16) == payload(cid, sequence, 16)
                    COUNTS["churn"] += 1
                await asyncio.sleep(min(10, max(0.2, DURATION / 10)))
    finally:
        writer.close()
        await writer.wait_closed()


def resources():
    global MAX_RSS_KIB, MAX_FDS
    if RUNTIME_PID is None:
        return {}
    status = Path(f"/proc/{RUNTIME_PID}/status").read_text()
    rss = int(re.search(r"VmRSS:\s+(\d+)", status)[1])
    fds = len(list(Path(f"/proc/{RUNTIME_PID}/fd").iterdir()))
    MAX_RSS_KIB = max(MAX_RSS_KIB, rss)
    MAX_FDS = max(MAX_FDS, fds)
    stat = Path(f"/proc/{RUNTIME_PID}/stat").read_text().rsplit(")", 1)[1].split()
    cpu_seconds = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
    return {"cpu_seconds": cpu_seconds, "rss_kib": rss, "fds": fds, "max_rss_kib": MAX_RSS_KIB, "max_fds": MAX_FDS}


def queue_samples():
    latest = {}
    for path in Path("log").glob("network*.log"):
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 65536))
            lines = stream.read().decode(errors="replace").splitlines()
        for line in lines:
            for node in ("MuxClient", "MuxServer"):
                if f"{node}: main line stats" in line:
                    latest[node] = dict(re.findall(r"([a-z-]+)=([a-z0-9]+)", line))
    return latest


async def samples(start):
    await start.wait()
    begin = time.monotonic()
    while True:
        await asyncio.sleep(5)
        print(json.dumps({"elapsed": round(time.monotonic() - begin, 2), **COUNTS, **resources(), "queues": queue_samples()}), flush=True)


def check_stats():
    logs = "\n".join(p.read_text(errors="replace") for p in Path("log").glob("network*.log"))
    for node in ("MuxClient", "MuxServer"):
        lines = [line for line in logs.splitlines() if f"{node}: main line stats" in line]
        assert lines, f"missing {node} statistics"
        for line in lines:
            for key in ("parent-output-queued-bytes", "parent-output-queue-charge", "parent-output-queue-items",
                        "parent-transport-paused", "parent-sources-throttled", "children-parent-write-paused",
                        "children-peer-flow-paused", "parent-output-throttle-ms", "parent-output-last-throttle-ms",
                        "parent-write-buffer-pause-threshold", "parent-write-buffer-resume-threshold", "parent-write-buffer-limit"):
                assert f"{key}=" in line, f"missing {key}"
            fields = dict(re.findall(r"([a-z-]+)=([a-z0-9]+)", line))
            charge = int(fields["parent-output-queue-charge"])
            wire = int(fields["parent-output-queued-bytes"])
            hard = int(fields["parent-write-buffer-limit"])
            pause = int(fields["parent-write-buffer-pause-threshold"])
            resume = int(fields["parent-write-buffer-resume-threshold"])
            assert 0 <= resume < pause < hard and wire <= charge <= hard
            if fields["parent-output-queue-items"] == "0":
                assert charge == wire == 0
            if fields["parent-sources-throttled"] == "no":
                assert fields["parent-output-throttle-ms"] == "0"
        # Single worker / fixed parent: establish that the measured parent held the population.
        observed = max(int(re.search(r"children-count=(\d+)", line)[1]) for line in lines)
        assert observed >= CHILDREN - max(1, CHILDREN // 100), f"{node} only observed {observed} attached children"
        print(json.dumps({"node": node, "max_children": observed, "last_stats": lines[-1]}), flush=True)
    assert "parent write queue resource limit exceeded" not in logs, "output hard limit closed parent"
    assert "closing child cid" not in logs, "child receive limit or unexpected child close"


def carrier_netem():
    # Only carrier packets enter band 3; each direction traverses one 40ms delay.
    commands = ["tc qdisc add dev lo root handle 1: prio bands 3",
                "tc qdisc add dev lo parent 1:3 handle 30: netem delay 40ms rate 100mbit limit 10000"]
    for field in ("sport", "dport"):
        commands.append(f"tc filter add dev lo protocol ip parent 1: prio 1 u32 match ip {field} 26881 0xffff flowid 1:3")
    for command in commands:
        subprocess.run(command.split(), check=True)


async def main():
    global RUNTIME_PID
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "cwd").resolve() == Path.cwd() and (entry / "exe").resolve().name == "Waterwall":
                RUNTIME_PID = int(entry.name)
                break
        except (OSError, RuntimeError):
            continue
    assert CHILDREN >= 1 and 1 <= HOT <= CHILDREN and DURATION >= 6
    print(json.dumps({"duration": DURATION, "children": CHILDREN, "batch": BATCH, "direction": DIRECTION,
                      "hot": HOT, "netem": NETEM, "fd_limit": resource.getrlimit(resource.RLIMIT_NOFILE)}), flush=True)
    if NETEM:
        carrier_netem()
    server = await asyncio.start_server(destination, "127.0.0.1", 26882)
    ready = [False] * CHILDREN
    start = asyncio.Event()
    tasks = [asyncio.create_task(child(cid, ready, start)) for cid in range(CHILDREN)]
    sampler = asyncio.create_task(samples(start))
    try:
        setup_deadline = time.monotonic() + 60
        while not all(ready):
            for task in tasks:
                if task.done():
                    task.result()
            assert time.monotonic() < setup_deadline, "scale setup did not establish every child"
            await asyncio.sleep(0.05)
        begin = time.monotonic()
        start.set()
        await asyncio.gather(*tasks)
        assert not ERRORS, ERRORS
        assert COUNTS["upload_sent"] == COUNTS["upload_received"]
        assert COUNTS["download_sent"] == COUNTS["download_received"]
        check_stats()
        print(json.dumps({"complete": True, "elapsed": round(time.monotonic() - begin, 2), **COUNTS, **resources()}), flush=True)
        if NETEM:
            subprocess.run(["ss", "-tinm", "sport", "=", ":26881"], check=True)
    finally:
        sampler.cancel()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        server.close()
        await server.wait_closed()
        for writer in list(WRITERS):
            writer.close()
        await asyncio.gather(*list(HANDLERS), return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
