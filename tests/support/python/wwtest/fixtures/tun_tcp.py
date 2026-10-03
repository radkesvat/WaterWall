"""Shared real TUN TCP namespace fixture and fixed byte-verifying exchange. Requires Linux
root/TUN/network namespaces; unavailable capabilities stay skips. Owns all spawned children/logs,
drains them in reverse order before namespace holders; callers own run-directory retention and
benchmark verdicts/workload."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

TESTS = Path(__file__).resolve().parents[4]
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


def preflight(mode):
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/dev/net/tun").is_char_device():
        raise Unavailable("requires Linux, root and /dev/net/tun")
    for tool in ("bash", "ip", "unshare", "nsenter", "ss", "sleep", "ethtool"):
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

    def configure(self, config):
        config["nodes"][0]["settings"]["gso"] = self.gso

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
            self.configure(config)
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
                match = re.search(r"configured framing: (TCPv4 GSO with checksum offload|checksum-only offload|raw IP) "
                                  r"\(GSO requested: (yes|no)\)", log)
                link = subprocess.run([*self.runtime, "ip", "-d", "link", "show", TUN],
                                      text=True, capture_output=True, timeout=5)
                if match and link.returncode == 0 and "UP" in link.stdout:
                    require(match[2] == ("yes" if self.gso else "no"), "wrong requested GSO setting")
                    self.checksum_enabled = match[1] != "raw IP"
                    self.gso_enabled = match[1] == "TCPv4 GSO with checksum offload"
                    if not self.checksum_enabled or (self.gso and not self.gso_enabled):
                        raise Unavailable("requested TUN offload mode unavailable; see runtime log")
                    require(self.gso_enabled == self.gso, "unexpected active segmentation mode")
                    expected = "vnet_hdr on" if self.checksum_enabled else "vnet_hdr off"
                    require(expected in link.stdout, "TUN framing did not match the selected setting")
                    features = output(*self.runtime, "ethtool", "-k", TUN)
                    require("tx-checksumming: on" in features, "TUN checksum offload was not active")
                    tso = "on" if self.gso_enabled else "off"
                    require("tx-tcp-segmentation: " + tso in features, "TUN TSO4 feature disagrees with active mode")
                    (self.directory / "tun-features.txt").write_text(features)
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
        match = re.search(r"offload reader summary: ordinary=(\d+) aggregates=(\d+) generated=(\d+).*"
                          r"malformed=(\d+) unsupported=(\d+) oversized=(\d+) intact=(\d+)", log)
        require(match is not None, "offload summary missing after shutdown")
        ordinary, aggregates, segments, malformed, unsupported, oversized, intact = map(int, match.groups())
        require(ordinary > 0, "run did not exercise ordinary offload-framed input")
        if not self.gso_enabled:
            require(aggregates == segments == intact == 0, "checksum-only run admitted GSO input")
        elif "enabled direct-pair trusted transport checksums" in log:
            require(aggregates > 0, "enabled run did not exercise GSO input")
            require(intact > 0 and segments == 0, "trusted run did not deliver GSO input intact")
        else:
            require(aggregates > 0, "enabled run did not exercise GSO input")
            require(intact == 0 and segments > aggregates, "ordinary run did not exercise GSO segmentation")
        require(malformed == unsupported == oversized == 0, "valid TCP workload produced rejected offload records")
        return {"ordinary": ordinary, "aggregates": aggregates, "segments": segments, "intact": intact}

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
            message = "fixture cleanup failed: " + "; ".join(errors)
            if exc_type is None:
                raise RuntimeError(message)
            print(message, file=sys.stderr, flush=True)


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
