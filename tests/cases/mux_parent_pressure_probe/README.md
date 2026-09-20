# Mux parent pressure probe

Run this through `tests/run_in_network_namespace.sh`, using the existing probe
runner. The config has one worker, one fixed TCP parent, 64/32 KiB pause/resume
thresholds and the production 128 MiB output limit. Four hot children upload and
download sequence-tagged batches; remaining children exchange small periodic
messages. A 0.5-second destination stall is followed by draining. A bounded
subset reconnects every fourth exchange and sends useful bytes immediately.
All streams check payload order and contents. Five-second samples report sender
and receiver progress separately, runtime RSS/FDs, and final mux statistics.

The registered functional cases run for seven seconds in both splice modes.
They check TCP composition and diagnostics; unit tests supply the deterministic
nonempty-release and exact boundary assertions.

For a frozen carrier scenario (run each direction and splice mode separately):

```bash
MUX_PRESSURE_SECONDS=180 MUX_PRESSURE_DIRECTION=both \
MUX_PRESSURE_NETEM=true WATERWALL_TEST_SPLICE=true \
bash tests/run_in_network_namespace.sh bash tests/run_waterwall_probe_case.sh \
  build/linux/Release/Waterwall tests/cases/mux_parent_pressure_probe 300 /usr/bin/python3
```

`MUX_PRESSURE_DIRECTION` accepts `upload`, `download`, or `both`. Netem filters
only carrier port 26881, with 40 ms delay per traversal and a configured
100 Mbit/s rate. It requires `tc`, netem, and namespace privileges. Failures are
not passes. The final `ss -tinm` output records effective carrier windows,
buffers and retransmissions; achieved throughput can be below the configured
rate. Do not retune socket defaults or the host based on a result.

For 2,000-child scale coverage, set `MUX_PRESSURE_CHILDREN=2000` and
`MUX_PRESSURE_SECONDS=1800`, with runner timeout at least 2000 seconds. Check
FD limits and memory headroom first. The driver uses asyncio, not one thread per
child. For long runs, quiet children exchange data every ten seconds. Use
172800 seconds for each requested 48-hour soak, and a corresponding larger
runner timeout. A shorter run is not soak evidence. Long-run output/log storage
must be bounded by the supervising runner; this fixture's ordinary short-test
runner does not collect or rotate a soak evidence archive.

For the default-threshold matrix, make a temporary copy of this case and remove
both `parent-write-buffer-*threshold` settings from both mux nodes in its
`config.json`. Keep limits, admission settings and idle policies unchanged.
`MUX_PRESSURE_BATCH` controls the hot transaction size (default 1 MiB); choose
and record it before running. The default transaction geometry does not guarantee
crossing the 16 MiB default pause threshold, so distinguish ordinary progress
from observed throttle episodes. A large backlog is not a receive-capacity
promise: individual and aggregate receive limits remain 24/128 MiB.

The full plan requires three 180-second repetitions for every direction, splice
mode and threshold profile, 30-minute scale runs in each mode, a multiworker
isolation scenario, and two 48-hour soaks. Record actual runs in an external results directory; these recipes do not
claim completion or add temporary result artifacts to source history.

For a single active writer, set `MUX_PRESSURE_CHILDREN=1 MUX_PRESSURE_HOT=1`.
For a 2,000-child mix, use `MUX_PRESSURE_CHILDREN=2000 MUX_PRESSURE_HOT=4`.
`MUX_PRESSURE_DIRECTION=upload` or `download` selects the hot direction.
Samples include process `cpu_seconds`, queue charge, local paused-child count,
and the aggregate gate. Individual writer holds can make
`children-parent-write-paused` nonzero while `parent-sources-throttled` is false;
aggregate throttle durations do not measure individual holds. Callback transition
counts and sparse-writer snapshot size are checked by the shared native fixture,
without adding production per-callback instrumentation.
