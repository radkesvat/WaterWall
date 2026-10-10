# WaterWall tests

CTest is the test selector. Native component fixtures, deterministic integration
cases, policy/runner checks, external cases, privileged cases and serial speed
workloads retain distinct execution requirements. The canonical lane policy,
build commands and planning timings live in [Developer Guide Part 6](../WaterWall-Docs/docs/05-devguides/part6-build-test-review.mdx).

The production `linux` tree keeps LTO enabled. Native units use the separate
`linux-unit-tests` tree, with asserted Debug and optimized `NDEBUG` Release.
Native fixtures can create runtime workers, substitute OS boundaries or fork
children; they are not all small library-only tests.

| Location | Responsibility |
| --- | --- |
| [unittests/](unittests/README.md) | Native sources organized by owning subsystem, immutable fixture inputs, and portable CMake execution entry points. |
| [support/](support/README.md) | Opt-in C assertions/runtime fixtures, standard-library Python helpers and shell runner mechanics. |
| [cmake/](cmake/README.md) | Shared registration functions and explicit native/integration family fragments. |
| `cases/<name>/` | Immutable configurations and optional probes; each directory README owns its purpose, topology, variants, prerequisites and verdict. |
| `speedtests/<name>/` | Fixed serial transfer workloads; local READMEs describe metrics and interpretation limits. |
| [benchmarks/](benchmarks/README.md) | Explicitly built diagnostic benchmarks, excluded from ordinary CTest gates. |
| `fixtures/` | Small runner regression inputs. |

Run from the repository root:

```bash
cmake --preset linux
cmake --build --preset linux -j8
bash tests/run_test_lane.sh support build/linux Release --no-tests=error
bash tests/run_test_lane.sh functional build/linux Release --no-tests=error
# Routine support, functional and external lanes:
bash tests/run_test_lane.sh all build/linux Release --no-tests=error
# Opt-in throughput and longer traffic/churn workloads:
bash tests/run_test_lane.sh speed build/linux Release --no-tests=error
bash tests/run_test_lane.sh stress build/linux Release --no-tests=error
# Requires the privileges/tools stated by the individual cases:
sudo -E bash tests/run_test_lane.sh privileged build/linux Release --no-tests=error

cmake --preset linux-unit-tests
cmake --build --preset linux-unit-debug -j8
ctest --preset linux-unit-debug --output-on-failure --no-tests=error
cmake --build --preset linux-unit-release -j8
ctest --preset linux-unit-release --output-on-failure --no-tests=error
```

The `linux` and `linux-packed` CTest presets exclude speed and stress workloads.
Short verified/unverified SpeedTestClient smoke cases remain in the functional
lane. Source-only policy checks run in production support once per source revision;
native Debug/Release presets exclude `source-policy` while retaining runtime and
build-policy checks. CI's manual `extended_tests` input enables the optional lanes.

Discover actual names and properties rather than maintaining a manual catalog:

```bash
ctest --preset linux -N
ctest --preset linux -N -V -R '^waterwall\.tls_roundtrip$'
ctest --preset linux --output-on-failure --no-tests=error -R '^waterwall\.tls_roundtrip$'
ctest --preset linux-unit-debug -N -L unit
ctest --preset linux-unit-release --show-only=json-v1
```

Choose the existing public runner that matches the verdict:

- `run_waterwall_case.sh`: built-in Tester roundtrip markers and accepted runtime exit.
- `run_waterwall_expected_failure_case.sh`: the selected startup/runtime failure diagnostic and enclosing expected-failure verdict.
- `run_waterwall_probe_case.sh`: an explicit Python/socket exchange and its own byte/order/exit checks.
- `run_waterwall_privileged_probe_case.sh`: explicit privileged prerequisites before the probe.
- `run_packet_analysis_case.sh`: the configured packet protocol/loss report.
- `run_waterwall_speedtest.sh`: complete SpeedTestClient report and successful runtime completion.

Use the namespace harness for deterministic cases, including direct debugging:

```bash
bash tests/run_in_network_namespace.sh \
  bash tests/run_waterwall_case.sh \
  "$PWD/build/linux/Release/Waterwall" "$PWD/tests/cases/tls_roundtrip" 60
```

The roundtrip runner copies inputs privately, writes core settings, watches the
existing tester marker, allows natural exit, then shuts down/reaps its child.
Early exits, crashes, unexpected post-success status and deadlines fail. Its
natural-exit grace defaults to 0.5 seconds;
`WATERWALL_TEST_SUCCESS_EXIT_GRACE_SECONDS=5` is an explicit debugging override.
`WATERWALL_TEST_SHOW_STDOUT_ON_SUCCESS=1` (also accepted through the existing
runner aliases) prints captured successful stdout; use verbose CTest to see it.

Native runs print their directory beneath
`<build>/test-runs/<configuration>/<test-name>/<invocation>/` before building.
Build and child output are separate. Cooperative build/run locking is per tree;
focused CTest still auto-builds a missing or stale native target. Manual builds
outside that coordination require an idle tree. Integration runs copy only the
needed case/inputs beneath `TMPDIR`; shared source inputs stay immutable.
Failures, interruptions, timeouts and initialized skips retain artifacts.
Successful enclosing tests remove them unless `WATERWALL_TEST_KEEP_RUN_DIR=1`;
an accepted expected failure is successful. Clean only idle generated outputs
with [cleanup_generated_outputs.sh](cleanup_generated_outputs.sh).

To add a test, choose the nearest actual contract fixture, then verify its
ownership and oracle instead of copying a pattern blindly. Keep topology,
stimulus, expectations and teardown visible. Put a short description beside the
entry point and a README beside each runnable case/workload. Register it in the
owning explicit [CMake fragment](cmake/README.md), preserving the appropriate
namespace, prerequisites, labels, locks, timeout and feature variants. Add
`workers.txt` only for a deliberate non-default worker count and explain it
locally. `allow-early-response=true` and `streaming-response=true` are useful
when the scenario must exercise bidirectional overlap. Keep JSON configuration
valid; documentation belongs outside JSON. Build and run focused Debug/Release
native coverage and the applicable production lane; shared changes use the full
matrix in Part 6.
