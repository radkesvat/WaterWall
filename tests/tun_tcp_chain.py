#!/usr/bin/env python3
"""Real TunDevice to PacketsToConnection to TcpConnector with GSO off/on and four 1MiB byte-verifying
connections. Optional serial iperf3: 1/4 streams, three alternating paired samples, 2s warm-up
plus10s measured, fixed flow tuples; reports throughput/CPU/retransmits without a gain threshold.
Linux root/TUN/namespaces; iperf3 additionally for speed. Speed artifacts always retained. CTest:
waterwall.tundevice_tcp_chain."""

import argparse
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.run_directory import RunDirectory
from wwtest.fixtures.tun_tcp import TESTS, WRAPPER, TRANSFER, TUN, OUT, PEER, CLIENT, SERVER, PORT, SOURCE_PORT, SKIP, Unavailable, require, command, output, stop, preflight, Fixture, integration















def cpu_seconds(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")








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
    run_directory = None
    success = False
    try:
        preflight(args.mode)
        binary = args.binary.resolve(strict=True)
        run_directory = RunDirectory("waterwall-tun-tcp-" + args.mode + "-")
        directory = run_directory.create()
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
        if run_directory is not None:
            keep = os.environ.get("WATERWALL_TEST_KEEP_RUN_DIR", "").lower() in ("1", "true", "yes", "on")
            run_directory.finish(0 if success else 1, keep_success=args.mode == "speed" or keep)



if __name__ == "__main__":
    sys.exit(main())
