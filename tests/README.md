# WaterWall tests

CTest is the test selector. Native component fixtures, deterministic integration
cases, policy/runner checks, external cases, privileged cases and serial speed
workloads retain distinct execution requirements. The canonical lane policy,
build commands and planning timings live in [Developer Guide Part 6](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/part6-build-test-review.mdx).

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

## Run a focused check

Choose the smallest test that exercises the changed behavior. For a codec or
component contract, select a [named native test](unittests/README.md). For a change
to how nodes work together, select the matching integration case. For example,
run the TLS roundtrip from the repository root with the current production binary.

```bash
cmake --preset linux
cmake --build --preset linux --config Release --target Waterwall -j8
ctest --preset linux --output-on-failure --no-tests=error -R '^waterwall\.tls_roundtrip$'
```

Use `ctest --preset linux -N -R 'tls'` to discover related cases. Stop once the
selected checks cover the changed behavior and affected callers. Expand locally
when a specific risk needs additional coverage or the task requests a broader run.
For lane commands and prerequisites, see [Developer Guide Part 6](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/part6-build-test-review.mdx#testing).

Linux CI runs the production lanes and complete Debug and Release native suites.
Source-only policy checks run once per revision in production support. Short
SpeedTestClient smoke cases run in the functional lane. Speed and stress workloads
are opt-in through CI's manual `extended_tests` input.

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
valid and documentation outside JSON. Run the new registration by its CTest name.
