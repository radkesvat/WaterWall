#!/usr/bin/env python3
"""Characterize the fixed 100,000-user managed VMess workload, without a speed gate.

Run through tests/run_in_network_namespace.sh, after provisioning the pinned peer:
  tests/run_in_network_namespace.sh python3 tests/vmess_scale.py \
    build/linux/Release/Waterwall build/test-tools/v2ray-5.53.0/v2ray

The complete workload is written before any measurement and has no tuning flags:
workers 1/4, concurrency 1/16, three ten-second samples of valid, invalid and
established-transfer phases. Every sample also probes an unrelated WaterWall TCP
chain. Each repetition rotates one credential through AuthenticationServer's real
API and waits for normal AuthenticationClient synchronization and authentication.
Only generated build/ artifacts contain results/configurations/logs. These are
host-specific characterizations, not throughput claims or optimization acceptance.
--prepare-only writes the same frozen inputs without executing the workload.
"""

import argparse
import concurrent.futures
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import types
import uuid

sys.dont_write_bytecode = True
import api_server_probe as api
import vmess_interop as interop
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import exact as socket_exact


BUILD = Path(__file__).resolve().parent.parent / "build"
HOST = interop.HOST
API_PORT, UNRELATED_PORT = 29938, 29939
PORTS = (29931, 29935, 29936, 29937)
USER_COUNT = 100000
POSITIONS = (0, USER_COUNT // 2, USER_COUNT - 1)
TOKEN = "0123456789abcdef" * 4  # Public, namespace-only fixture credential.
PAYLOAD = bytes(range(256)) * 256
WORKLOAD = {
    "users": USER_COUNT, "workers": [1, 4], "concurrency": [1, 16], "repetitions": 3,
    "phase_seconds": 10, "phase_order": ["valid", "invalid", "transfer"],
    "credential_rows": list(POSITIONS), "cipher": "aes-128-gcm", "transport": "tcp",
    "valid_probe_bytes": 128, "transfer_block_bytes": len(PAYLOAD),
    "unrelated_probe_interval_seconds": 0.02, "socket_timeout_seconds": 4,
    "pull_interval_ms": 2000, "handshake_timeout_ms": 3000,
    "startup_deadline_seconds": 180, "refresh_deadline_seconds": 180,
    "process_sample_interval_seconds": 0.1,
    "decision": "characterization only; no minimum throughput or relative-gain gate",
    "host_requirements": ["Linux /proc", "private network namespace with only loopback",
                          "native production WaterWall", "pinned V2Ray 5.53.0",
                          "no concurrent compilation or other benchmark workloads"],
    "limitations": ["candidate positions refer to input rows, not product instrumentation",
                    "loopback Python echo/reference client may constrain measured throughput",
                    "CPU and RSS include co-located AuthenticationServer and AuthenticationClient",
                    "refresh includes periodic-pull wait and lazy VMess credential-view rebuild"],
}


def exact(stream, size):
    return socket_exact(stream, size, eof_error=EOFError)


def identity(index):
    return str(uuid.UUID(int=(0xA2150010000040008000000000000000 | (index + 1))))


def quantiles(values):
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "p50_ms": None, "p95_ms": None, "p99_ms": None, "max_ms": None}
    def percentile(fraction):
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))] * 1000
    return {"count": len(ordered), "p50_ms": percentile(.5), "p95_ms": percentile(.95),
            "p99_ms": percentile(.99), "max_ms": ordered[-1] * 1000}


def process_usage(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
    memory = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            name, value, _ = line.split()
            memory[name[:-1]] = int(value) * 1024
    return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
            "rss_bytes": memory.get("VmRSS", 0), "lifetime_peak_rss_bytes": memory.get("VmHWM", 0)}


def query(node, operation, body=None):
    identifier = "scale"
    request = {"id": identifier, "auth": {"client": "scale", "token": TOKEN},
               "selector": {"config": "vmess-scale", "node": node}, "operation": operation,
               "content_type": "application/json", "body_encoding": "utf8",
               "body": json.dumps({} if body is None else body)}
    with socket.create_connection((HOST, API_PORT), timeout=4) as stream, stream.makefile("rb") as reader:
        stream.sendall(api.frame(request))
        response = api.response(reader, identifier)
    if response["error"] is not None or response["result"]["code"] != 0:
        raise RuntimeError(f"API {node}/{operation} refused: {response}")
    return json.loads(response["result"]["body"])


def prepare(root, workers):
    args = types.SimpleNamespace(auth="database", protocol="tcp", scenario="roundtrip",
                                 transport="tcp", cipher="aes-128-gcm", workers=workers)
    interop.inputs(root, args)
    with (root / "users.json").open("w") as output:
        output.write('{"users":[')
        for index in range(USER_COUNT):
            if index:
                output.write(",")
            json.dump({"id": index + 1, "name": f"scale-{index}", "password": identity(index),
                       "enabled": True}, output, separators=(",", ":"))
        output.write("]}")
    config = json.loads((root / "config.json").read_text())
    config["name"] = "vmess-scale"
    for node in config["nodes"]:
        if node["type"] == "AuthenticationClient":
            node["settings"].update({"pull-interval-ms": WORKLOAD["pull_interval_ms"],
                                     "request-timeout-ms": 120000,
                                     "sync-max-users": USER_COUNT, "sync-max-bytes": 268435456})
        if node["type"] == "VmessServer":
            node["settings"]["handshake-timeout-ms"] = WORKLOAD["handshake_timeout_ms"]
    config["nodes"].extend([
        {"name": "scale-api-listener", "type": "TcpListener", "next": "scale-api",
         "settings": {"address": HOST, "port": API_PORT}},
        {"name": "scale-api", "type": "APIServer", "settings": {"clients": [{"name": "scale", "token": TOKEN,
         "allow": [{"config": "vmess-scale", "node": "auth-db",
                    "operations": ["get-user", "change-user-password"]},
                   {"config": "vmess-scale", "node": "auth-client", "operations": ["status"]}]}]}},
        {"name": "unrelated-listener", "type": "TcpListener", "next": "unrelated-out",
         "settings": {"address": HOST, "port": UNRELATED_PORT, "nodelay": True}},
        {"name": "unrelated-out", "type": "TcpConnector", "settings": {
            "address": HOST, "port": interop.TARGET_PORT, "nodelay": True, "fastopen": False}},
    ])
    (root / "config.json").write_text(json.dumps(config))
    (root / "core.json").write_text(json.dumps(core_config(workers=workers, ram_profile="server",
                                                          loglevel="WARN", splice=True)))
    reference = json.loads((root / "v2ray.json").read_text())
    reference["log"]["loglevel"] = "warning"
    inbound = reference["inbounds"][0]
    outbound = reference["outbounds"][0]
    reference["inbounds"], reference["outbounds"] = [], []
    reference["routing"] = {"rules": []}
    ids = [identity(index) for index in POSITIONS] + [identity(USER_COUNT + 1)]
    for index, (port, user_id) in enumerate(zip(PORTS, ids)):
        item = json.loads(json.dumps(inbound))
        item.update({"port": port, "tag": f"in-{index}"})
        reference["inbounds"].append(item)
        item = json.loads(json.dumps(outbound))
        item["tag"] = f"out-{index}"
        item["settings"]["vnext"][0]["users"][0]["id"] = user_id
        reference["outbounds"].append(item)
        reference["routing"]["rules"].append({"type": "field", "inboundTag": [f"in-{index}"],
                                                 "outboundTag": f"out-{index}"})
    (root / "v2ray.json").write_text(json.dumps(reference))


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        with contextlib.suppress(OSError):
            while data := self.request.recv(65536):
                self.request.sendall(data)


def socks(port):
    stream = socket.create_connection((HOST, port), timeout=WORKLOAD["socket_timeout_seconds"])
    try:
        stream.sendall(b"\x05\x01\x00")
        if exact(stream, 2) != b"\x05\x00":
            raise AssertionError("SOCKS authentication changed")
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + interop.TARGET_PORT.to_bytes(2, "big"))
        header = exact(stream, 4)
        if header[:3] != b"\x05\x00\x00":
            raise ConnectionError("reference SOCKS CONNECT failed")
        address_length = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            address_length = exact(stream, 1)[0]
        if address_length is None:
            raise AssertionError("invalid SOCKS reply address")
        exact(stream, address_length + 2)
        return stream
    except BaseException:
        stream.close()
        raise


def exchange(port, payload=PAYLOAD[:128]):
    with socks(port) as stream:
        stream.sendall(payload)
        if exact(stream, len(payload)) != payload:
            raise AssertionError("VMess application bytes differ")


def phase(root, waterwall, reference, kind, concurrency, middle_port):
    deadline = time.monotonic() + WORKLOAD["phase_seconds"]
    start = time.monotonic()
    load_start = os.getloadavg()
    pids = {"waterwall": waterwall.child.pid, "reference": reference.child.pid, "harness": os.getpid()}
    before = {name: process_usage(pid) for name, pid in pids.items()}
    samples, latencies, unrelated = [], [], []
    errors = {}
    counts = {"completed": 0, "bytes": 0, "attempted": 0}
    lock = threading.Lock()
    stop = threading.Event()
    selected_ports = (PORTS[0], middle_port, PORTS[2])

    def record_error(error):
        with lock:
            label = type(error).__name__
            errors[label] = errors.get(label, 0) + 1

    def worker(index):
        sequence = index
        stream = None
        try:
            while time.monotonic() < deadline:
                began = time.monotonic()
                with lock:
                    counts["attempted"] += 1
                try:
                    if kind == "invalid":
                        with socket.create_connection((HOST, interop.WIRE_PORT), timeout=4) as candidate:
                            candidate.sendall(os.urandom(42))
                            if candidate.recv(1) != b"":
                                raise AssertionError("invalid AuthID received protocol/application data")
                        amount = 0
                    elif kind == "valid":
                        exchange(selected_ports[sequence % 3])
                        amount = 128
                    else:
                        if stream is None:
                            stream = socks(selected_ports[sequence % 3])
                        stream.sendall(PAYLOAD)
                        if exact(stream, len(PAYLOAD)) != PAYLOAD:
                            raise AssertionError("transfer payload differs")
                        amount = len(PAYLOAD)
                    with lock:
                        counts["completed"] += 1
                        counts["bytes"] += amount
                        latencies.append(time.monotonic() - began)
                except (OSError, EOFError, ConnectionError) as error:
                    record_error(error)
                    if stream is not None:
                        stream.close()
                        stream = None
                sequence += 1
        finally:
            if stream is not None:
                stream.close()

    def probe():
        try:
            with socket.create_connection((HOST, UNRELATED_PORT), timeout=4) as stream:
                while not stop.is_set():
                    began = time.monotonic()
                    stream.sendall(b"responsiveness")
                    if exact(stream, 14) != b"responsiveness":
                        raise AssertionError("unrelated chain bytes differ")
                    unrelated.append(time.monotonic() - began)
                    stop.wait(WORKLOAD["unrelated_probe_interval_seconds"])
        except (OSError, EOFError) as error:
            record_error(error)

    def monitor():
        while not stop.is_set():
            samples.append({name: process_usage(pid) for name, pid in pids.items()})
            stop.wait(WORKLOAD["process_sample_interval_seconds"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency + 2) as pool:
        probe_result, monitor_result = pool.submit(probe), pool.submit(monitor)
        try:
            jobs = [pool.submit(worker, index) for index in range(concurrency)]
            for job in jobs:
                job.result(timeout=WORKLOAD["phase_seconds"] + 10)
        finally:
            stop.set()
        probe_result.result(timeout=6)
        monitor_result.result(timeout=6)
    elapsed = time.monotonic() - start
    waterwall.check_running("WaterWall exited during characterization")
    after = {name: process_usage(pid) for name, pid in pids.items()}
    usage = {}
    for name in pids:
        usage[name] = {"cpu_seconds": after[name]["cpu_seconds"] - before[name]["cpu_seconds"],
                       "rss_start_bytes": before[name]["rss_bytes"], "rss_end_bytes": after[name]["rss_bytes"],
                       "lifetime_peak_rss_bytes": after[name]["lifetime_peak_rss_bytes"],
                       "sampled_peak_rss_bytes": max([before[name]["rss_bytes"], after[name]["rss_bytes"]] +
                                                     [sample[name]["rss_bytes"] for sample in samples])}
        usage[name]["cpu_percent_one_core"] = usage[name]["cpu_seconds"] / elapsed * 100
    return {"phase": kind, "concurrency": concurrency, "elapsed_seconds": elapsed, **counts,
            "host_load_average_start": load_start, "host_load_average_end": os.getloadavg(),
            "operations_per_second": counts["completed"] / elapsed,
            "verified_roundtrip_mib_per_second": counts["bytes"] * 2 / elapsed / (1024 * 1024),
            "latency": quantiles(latencies), "unrelated_latency": quantiles(unrelated),
            "errors": errors, "processes": usage}


def refresh_once(waterwall, middle_port):
    account_id = str(POSITIONS[1] + 1)
    original = identity(POSITIONS[1])
    replacement = identity(USER_COUNT + 1)
    next_port = PORTS[3] if middle_port == PORTS[1] else PORTS[1]
    next_password = replacement if next_port == PORTS[3] else original
    current = query("auth-db", "get-user", {"id": account_id})
    before = process_usage(waterwall.child.pid)
    began = time.monotonic()
    ack = query("auth-db", "change-user-password", {"id": account_id, "if_match": current["edit_token"],
                                                     "password": next_password})
    deadline = began + WORKLOAD["refresh_deadline_seconds"]
    peak = before["rss_bytes"]
    observations = []
    applied = None
    while time.monotonic() < deadline:
        waterwall.check_running("WaterWall exited during refresh")
        state = query("auth-client", "status")
        peak = max(peak, process_usage(waterwall.child.pid)["rss_bytes"])
        observations.append({"elapsed_seconds": time.monotonic() - began,
                             "phase": state["sync_phase"], "users": state["users_count"],
                             "revision": state["applied_config_revision"]})
        if int(state["applied_config_revision"]) >= int(ack["config_revision"]):
            applied = time.monotonic() - began
            break
        time.sleep(.2)
    if applied is None:
        raise TimeoutError("credential update did not reach AuthenticationClient within frozen deadline")
    exchange(next_port)
    rebuilt = time.monotonic() - began
    revoked = False
    try:
        exchange(middle_port)
    except (OSError, EOFError, ConnectionError):
        revoked = True
    if not revoked:
        raise AssertionError("rotated credential still admitted after completed refresh")
    after = process_usage(waterwall.child.pid)
    return next_port, {"applied_seconds": applied, "new_credential_authenticated_seconds": rebuilt,
                       "old_credential_rejected": revoked, "sampled_peak_rss_bytes": max(peak, after["rss_bytes"]),
                       "lifetime_peak_rss_bytes": after["lifetime_peak_rss_bytes"],
                       "cpu_seconds": after["cpu_seconds"] - before["cpu_seconds"], "observations": observations}


def refresh(waterwall, middle_port):
    stop = threading.Event()
    latencies, failures = [], []
    def probe():
        try:
            with socket.create_connection((HOST, UNRELATED_PORT), timeout=4) as stream:
                while not stop.is_set():
                    began = time.monotonic()
                    stream.sendall(b"responsiveness")
                    if exact(stream, 14) != b"responsiveness":
                        raise AssertionError("refresh unrelated chain bytes differ")
                    latencies.append(time.monotonic() - began)
                    stop.wait(WORKLOAD["unrelated_probe_interval_seconds"])
        except (OSError, EOFError) as error:
            failures.append(type(error).__name__)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        task = executor.submit(probe)
        try:
            next_port, result = refresh_once(waterwall, middle_port)
        finally:
            stop.set()
        task.result(timeout=6)
    result.update({"unrelated_latency": quantiles(latencies), "unrelated_errors": failures})
    return next_port, result


def run(args):
    if platform.system() != "Linux" or not Path("/proc/self/stat").is_file():
        raise RuntimeError("fixed workload requires Linux /proc")
    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces != {"lo"}:
        raise RuntimeError("run the fixed workload inside tests/run_in_network_namespace.sh")
    version = subprocess.run([str(args.reference), "version"], check=True, capture_output=True,
                             text=True, timeout=5).stdout
    if not version.startswith("V2Ray 5.53.0 "):
        raise RuntimeError("reference must be pinned V2Ray 5.53.0")
    output = args.output.resolve()
    if not output.is_relative_to(BUILD.resolve()):
        raise RuntimeError("scale artifacts must be inside the repository build/ directory")
    output.mkdir(parents=True, exist_ok=True)
    directory = RunDirectory("vmess-scale-", parent=output)
    root = directory.create()
    report = {"workload": WORKLOAD, "host": {"platform": platform.platform(), "cpu_count": os.cpu_count(),
               "affinity": sorted(os.sched_getaffinity(0))}, "reference": version.splitlines()[0],
              "samples": [], "refreshes": [], "status": "prepared" if args.prepare_only else "running"}
    frozen_binary = root / "Waterwall"
    shutil.copy2(args.waterwall, frozen_binary)
    report["waterwall_sha256"] = hashlib.sha256(frozen_binary.read_bytes()).hexdigest()
    (root / "workload.json").write_text(json.dumps(report, indent=2))
    status = 1
    def save():
        (root / "results.json").write_text(json.dumps(report, indent=2))
    try:
        for workers in WORKLOAD["workers"]:
            case = root / f"workers-{workers}"
            case.mkdir()
            prepare(case, workers)
            if args.prepare_only:
                continue
            with EchoServer((HOST, interop.TARGET_PORT), Echo) as backend:
                thread = threading.Thread(target=backend.serve_forever, daemon=True)
                thread.start()
                try:
                    with Process([str(frozen_binary)], cwd=case, log_path=case / "waterwall.log") as waterwall:
                        began = time.monotonic()
                        while True:
                            waterwall.check_running("WaterWall exited before scale readiness")
                            try:
                                state = query("auth-client", "status")
                                if state["can_authenticate"] and int(state["users_count"]) == USER_COUNT:
                                    break
                            except (OSError, EOFError):
                                pass
                            if time.monotonic() - began >= WORKLOAD["startup_deadline_seconds"]:
                                raise TimeoutError("100,000 users did not synchronize within frozen startup deadline")
                            time.sleep(.1)
                        report.setdefault("startup", []).append({"workers": workers, "seconds": time.monotonic() - began,
                                                                 **process_usage(waterwall.child.pid)})
                        with Process([str(args.reference), "run", "-c", str(case / "v2ray.json")],
                                     cwd=case, log_path=case / "v2ray.log") as reference:
                            ready = time.monotonic() + 10
                            while True:
                                reference.check_running("reference exited before readiness")
                                try:
                                    exchange(PORTS[0])
                                    break
                                except OSError:
                                    if time.monotonic() >= ready:
                                        raise
                                    time.sleep(.05)
                            middle_port = PORTS[1]
                            for repetition in range(WORKLOAD["repetitions"]):
                                for concurrency in WORKLOAD["concurrency"]:
                                    for kind in WORKLOAD["phase_order"]:
                                        result = phase(case, waterwall, reference, kind, concurrency, middle_port)
                                        result.update({"workers": workers, "repetition": repetition})
                                        report["samples"].append(result)
                                        save()
                                        print(json.dumps({key: result[key] for key in ("workers", "repetition", "phase",
                                              "concurrency", "completed", "errors", "operations_per_second")}), flush=True)
                                middle_port, result = refresh(waterwall, middle_port)
                                result.update({"workers": workers, "repetition": repetition})
                                report["refreshes"].append(result)
                                save()
                        interop.stop_waterwall(waterwall)
                finally:
                    backend.shutdown()
                    thread.join(timeout=5)
        report["status"] = "prepared" if args.prepare_only else "complete"
        status = 0
    except BaseException as error:
        report["status"] = "inconclusive on this host"
        report["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save()
        directory.finish(status, keep_success=True)
    print(root / "results.json", flush=True)


if __name__ == "__main__":
    install_termination_handler()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("waterwall", type=lambda value: Path(value).resolve())
    parser.add_argument("reference", type=lambda value: Path(value).resolve())
    parser.add_argument("--output", type=Path, default=BUILD / "characterization")
    parser.add_argument("--prepare-only", action="store_true")
    run(parser.parse_args())
