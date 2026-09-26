#!/usr/bin/env python3
"""Correctness and optional iperf3 coverage of the real TUN TCP bridge chain."""

import argparse
import json
import math
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


TESTS = Path(__file__).resolve().parent
WRAPPER = TESTS / "run_in_network_namespace.sh"
TRANSFER = TESTS / "tun_tcp_chain_transfer.py"
TUN, OUT, PEER = "wwtcp0", "wwtcpout0", "wwtcppeer0"
CLIENT, SERVER = "198.19.0.1", "198.18.0.2"
PORT, SOURCE_PORT = 5201, 40000
SKIP = 77


class Unavailable(RuntimeError):
    """A required host capability is absent; never report this as coverage."""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=kwargs.pop("timeout", 10), **kwargs)


def output(*args):
    return command(*args, capture_output=True).stdout


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise RuntimeError(f"process {process.pid} did not stop gracefully")


def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def preflight(mode):
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/dev/net/tun").is_char_device():
        raise Unavailable("requires Linux, root and /dev/net/tun")
    for tool in ("bash", "ip", "unshare", "nsenter", "ss", "sleep"):
        if shutil.which(tool) is None:
            raise Unavailable(f"required command is missing: {tool}")
    if mode == "speed":
        if shutil.which("iperf3") is None:
            raise Unavailable("optional speed test requires iperf3")
        if "--cport" not in output("iperf3", "--help"):
            raise Unavailable("iperf3 must support --cport for repeatable data-flow ports")
    # Use the same namespace harness as other integration cases. Probe TUN
    # and veth admission before starting WaterWall, so a host denial is a skip.
    probe = subprocess.run(
        ["bash", str(WRAPPER), "bash", "-ec",
         "ip tuntap add dev wwprobe0 mode tun\nip link add wwprobe1 type veth peer name wwprobe2"],
        text=True, capture_output=True, timeout=10)
    if probe.returncode:
        raise Unavailable("network namespace/TUN/veth preflight failed: " + probe.stderr.strip())


class Fixture:
    """One fresh runtime/server namespace pair, shared by both test modes."""

    def __init__(self, binary, directory, gso):
        self.binary, self.directory, self.gso = binary, directory, gso
        self.processes, self.logs = [], []
        self.waterwall = None

    def spawn(self, args, log_name):
        log = (self.directory / log_name).open("w")
        self.logs.append(log)
        process = subprocess.Popen(args, cwd=self.directory, stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(process)
        return process

    def namespace(self, name):
        holder = self.spawn(["bash", str(WRAPPER), "sleep", "600"], name + ".log")
        deadline = time.monotonic() + 5
        while holder.poll() is None:
            if os.readlink(f"/proc/{holder.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                return ["nsenter", "-t", str(holder.pid), "-n"]
            require(time.monotonic() < deadline, "namespace startup timed out")
            time.sleep(.02)
        raise RuntimeError("namespace holder exited during startup")

    def __enter__(self):
        self.directory.mkdir()
        try:
            self.runtime, self.peer = self.namespace("runtime"), self.namespace("peer")
            command(*self.runtime, "ip", "link", "add", OUT, "type", "veth", "peer", "name", PEER)
            command(*self.runtime, "ip", "link", "set", PEER, "netns", self.peer[2])
            command(*self.runtime, "ip", "addr", "add", "198.18.0.1/24", "dev", OUT)
            command(*self.runtime, "ip", "link", "set", OUT, "mtu", "1500", "up")
            command(*self.peer, "ip", "addr", "add", SERVER + "/24", "dev", PEER)
            command(*self.peer, "ip", "link", "set", PEER, "mtu", "1500", "up")
            # Replies from the server arrive on veth while the unmarked route
            # points at TUN. Adjust reverse-path filtering only inside runtime.
            command(*self.runtime, sys.executable, "-c",
                    "from pathlib import Path; "
                    "[Path('/proc/sys/net/ipv4/conf/'+n+'/rp_filter').write_text('0\\n') "
                    f"for n in ('all','default','{OUT}')]")
            command(*self.runtime, "ip", "rule", "add", "fwmark", "99", "lookup", "100", "priority", "100")
            command(*self.runtime, "ip", "route", "add", "198.18.0.0/24", "dev", OUT,
                    "src", "198.18.0.1", "table", "100")
            config = json.loads((TESTS / "cases/tundevice_tcp_chain/config.json").read_text())
            config["nodes"][0]["settings"]["gso"] = self.gso
            core = {
                "log": {"path": "log/", **{
                    key: {"loglevel": "INFO", "file": key + ".log", "console": True}
                    for key in ("internal", "core", "network", "dns")}},
                "configs": ["config.json"],
                "misc": {"workers": 4, "ram-profile": "server", "mtu": 1500,
                         "splice": False, "try-enabling-bbr": False}}
            for name, value in (("core.json", core), ("config.json", config)):
                (self.directory / name).write_text(json.dumps(value, indent=2) + "\n")
            self.waterwall = self.spawn([*self.runtime, str(self.binary)], "waterwall.log")
            deadline = time.monotonic() + 10
            while True:
                require(self.waterwall.poll() is None, "WaterWall exited during startup")
                log = (self.directory / "waterwall.log").read_text()
                match = re.search(r"configured framing: (TCPv4 GSO|raw IP) \(GSO requested: (yes|no)\)", log)
                link = subprocess.run([*self.runtime, "ip", "-d", "link", "show", TUN],
                                      text=True, capture_output=True, timeout=5)
                if match and link.returncode == 0 and "UP" in link.stdout:
                    require(match[2] == ("yes" if self.gso else "no"), "wrong requested GSO setting")
                    if self.gso and match[1] == "raw IP":
                        raise Unavailable("GSO requested but WaterWall fell back to raw-IP framing; see runtime log")
                    expected = "vnet_hdr on" if self.gso else "vnet_hdr off"
                    require(expected in link.stdout, "TUN framing did not match the selected setting")
                    (self.directory / "tun-link.txt").write_text(link.stdout)
                    break
                require(time.monotonic() < deadline, "TUN startup timed out")
                time.sleep(.05)
            command(*self.runtime, "ip", "route", "replace", SERVER + "/32", "dev", TUN, "src", CLIENT)
            plain = output(*self.runtime, "ip", "route", "get", SERVER, "from", CLIENT)
            marked = output(*self.runtime, "ip", "route", "get", SERVER, "mark", "99")
            require("dev " + TUN in plain and "dev " + OUT in marked, "chain routing would bypass or loop through TUN")
            (self.directory / "routes.txt").write_text(plain + marked)
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def wait_server(self, process):
        deadline = time.monotonic() + 5
        while True:
            require(process.poll() is None, "server exited before listening")
            if output(*self.peer, "ss", "-H", "-ltn", f"sport = :{PORT}"):
                return
            require(time.monotonic() < deadline, "server did not start listening")
            time.sleep(.02)

    def finish(self):
        require(self.waterwall.poll() is None, "WaterWall exited before workload completed")
        stop(self.waterwall)
        require(self.waterwall.returncode in (0, 143), "WaterWall did not complete orderly shutdown")
        log = (self.directory / "waterwall.log").read_text()
        if not self.gso:
            require("GSO reader summary" not in log, "disabled run used the GSO reader")
            return None
        match = re.search(r"GSO reader summary: ordinary=(\d+) aggregates=(\d+) generated=(\d+).*"
                          r"malformed=(\d+) unsupported=(\d+) oversized=(\d+)", log)
        require(match is not None, "GSO summary missing after shutdown")
        ordinary, aggregates, segments, malformed, unsupported, oversized = map(int, match.groups())
        require(aggregates > 0 and segments > aggregates, "enabled run did not exercise GSO segmentation")
        require(malformed == unsupported == oversized == 0, "valid TCP workload produced rejected offload records")
        return {"ordinary": ordinary, "aggregates": aggregates, "segments": segments}

    def __exit__(self, exc_type, exc_value, traceback):
        errors = []
        for process in reversed(self.processes):
            try:
                stop(process)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(str(error))
        for log in self.logs:
            log.close()
        if errors:
            raise RuntimeError("fixture cleanup failed: " + "; ".join(errors)) from exc_value


def integration(fixture):
    common = ["--address", SERVER, "--port", str(PORT), "--connections", "4", "--bytes", "1048576"]
    server = fixture.spawn([*fixture.peer, sys.executable, str(TRANSFER), "server", *common], "server.log")
    fixture.wait_server(server)
    client = [*fixture.runtime, sys.executable, str(TRANSFER), "client", *common,
              "--bind", CLIENT, "--source-port", str(SOURCE_PORT)]
    with (fixture.directory / "client.json").open("w") as log:
        command(*client, stdout=log, timeout=35)
    server.wait(timeout=5)
    require(server.returncode == 0, "byte-verifying server failed")
    result = json.loads((fixture.directory / "client.json").read_text())
    received = json.loads((fixture.directory / "server.log").read_text().splitlines()[-1])
    for counters in (result, received):
        require(counters["verified"] and counters["connections"] == 4 and
                counters["upload_bytes"] == counters["download_bytes"] == 4 * 1048576,
                "incomplete bidirectional payload verification")
    return {key: value for key, value in result.items() if key != "role"}


def speed(fixture, streams):
    server = fixture.spawn([*fixture.peer, "iperf3", "-s", "-1", "-B", SERVER, "-p", str(PORT), "-J"],
                           "iperf-server.json")
    fixture.wait_server(server)
    begin_cpu, begin_wall = cpu_seconds(fixture.waterwall.pid), time.monotonic()
    with (fixture.directory / "iperf-client.json").open("w") as log:
        command(*fixture.runtime, "iperf3", "-4", "-c", SERVER, "-B", CLIENT, "-p", str(PORT),
                "--cport", str(SOURCE_PORT), "-P", str(streams), "-t", "10", "-O", "2", "-J",
                "--connect-timeout", "5000", "--get-server-output", stdout=log, timeout=35)
    cpu, wall = cpu_seconds(fixture.waterwall.pid) - begin_cpu, time.monotonic() - begin_wall
    server.wait(timeout=5)
    require(server.returncode == 0, "iperf3 server failed")
    data = json.loads((fixture.directory / "iperf-client.json").read_text())
    require("error" not in data, "iperf3 reported an error: " + str(data.get("error")))
    tuples = sorted((flow["local_host"], flow["local_port"], flow["remote_host"], flow["remote_port"])
                    for flow in data["start"]["connected"])
    require(tuples == [(CLIENT, SOURCE_PORT + i, SERVER, PORT) for i in range(streams)],
            "iperf3 data-flow tuples changed; worker placement is not repeatable")
    received, sent = data["end"]["sum_received"], data["end"]["sum_sent"]
    require(math.isfinite(received["bits_per_second"]) and received["bits_per_second"] > 0 and
            received["seconds"] >= 9, "iperf3 did not produce a complete throughput sample")
    return {"streams": streams, "receiver_bps": received["bits_per_second"],
            "sender_bps": sent["bits_per_second"], "retransmits": sent.get("retransmits"),
            "receiver_seconds": received["seconds"], "flow_tuples": tuples,
            "waterwall_cpu_seconds": round(cpu, 4), "client_wall_seconds": round(wall, 4)}


def speed_summary(results):
    summary = []
    for streams in (1, 4):
        groups = {state: [r["receiver_bps"] for r in results if r["streams"] == streams and r["gso"] == state]
                  for state in (False, True)}
        medians = {state: statistics.median(values) for state, values in groups.items()}
        changes = []
        for pair in (1, 2, 3):
            rates = {r["gso"]: r["receiver_bps"] for r in results if r["streams"] == streams and r["pair"] == pair}
            changes.append(100 * (rates[True] / rates[False] - 1))
        summary.append({"streams": streams, "off_median_bps": medians[False], "on_median_bps": medians[True],
                        "off_range_bps": [min(groups[False]), max(groups[False])],
                        "on_range_bps": [min(groups[True]), max(groups[True])],
                        "median_change_percent": 100 * (medians[True] / medians[False] - 1),
                        "paired_change_percent": changes})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("integration", "speed"), required=True)
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise RuntimeError(f"test runner interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    directory = None
    success = False
    try:
        preflight(args.mode)
        binary = args.binary.resolve(strict=True)
        directory = Path(tempfile.mkdtemp(prefix="waterwall-tun-tcp-" + args.mode + "-"))
        print(f"Artifacts: {directory}", flush=True)
        results = []
        workloads = [(None, None, state) for state in (False, True)]
        if args.mode == "speed":
            workloads = [(streams, pair, state) for streams in (1, 4) for pair in (1, 2, 3)
                         for state in ((False, True) if (pair + (streams == 4)) % 2 else (True, False))]
            print("Fixed workload: 4 workers, MTU1500, server RAM profile, 1/4 streams, 3 paired runs, "
                  "2s warm-up +10s measured; fixed data-flow ports; no throughput pass/fail threshold.", flush=True)
        for streams, pair, enabled in workloads:
            name = f"p{streams}-pair{pair}-" if streams else ""
            name += "on" if enabled else "off"
            with Fixture(binary, directory / name, enabled) as fixture:
                result = speed(fixture, streams) if streams else integration(fixture)
                result.update({"sample": name, "gso": enabled, "pair": pair,
                               "gso_counters": fixture.finish()})
            results.append(result)
            (directory / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(json.dumps(result), flush=True)
        if args.mode == "speed":
            summary = speed_summary(results)
            (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print("Throughput comparison (measurements only): " + json.dumps(summary), flush=True)
        success = True
        return 0
    except Unavailable as error:
        print(f"SKIP: {error}", flush=True)
        return SKIP
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        if directory:
            keep = os.environ.get("WATERWALL_TEST_KEEP_RUN_DIR", "").lower() in ("1", "true", "yes", "on")
            if success and args.mode == "integration" and not keep:
                shutil.rmtree(directory)
            else:
                print(f"Retained artifacts: {directory}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
