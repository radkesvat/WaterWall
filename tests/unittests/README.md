# Native tests

Native tests range from pure library checks to runtime/component fixtures with
workers, callbacks, OS seams and subprocesses. Each executable source's opening
comment describes the actual contract, important scenarios, limitations and
CTest selections. Auxiliary modules refer to their owning driver.

| Directory | Owning contract |
| --- | --- |
| `base/` | Utilities, codecs, portability, system/load observations and standalone headers. |
| `crypto/` | Crypto/checksum vectors, dispatch and failure boundaries. |
| `bufio/` | Buffers, pools, views and splice representation/stream behavior. |
| `net/` | Lines, chains, sockets, timers, event backends and worker scheduling. |
| `net/worker/` | Explicit worker-suite driver, separate accessor/message/teardown/pipe/HalfDuplex modules and the required shared runtime fixture. |
| `core/` | Settings, startup, node/identity indexes, signals and application lifecycle. |
| `devices/` | TUN/capture/raw device boundaries, reader/writer lifetime and platform variants. |
| `lwip/` | Packet stack, worker engines and protocol/checksum fixtures. |
| `tunnels/<family>/` | Protocol and transform contracts; platform/no-splice variants stay beside their family. |
| `fixtures/` | Immutable QUIC vectors and their generator, retained together without regeneration. |

Shared reusable fixtures live under [support/c/fixtures](../support/README.md).
Scenario-only helpers remain beside their suite. Public CMake execution and
portable/Windows registration entry files keep their paths in this directory;
[cmake/native](../cmake/README.md) contains the explicit registration bodies.

## Run focused native tests

Select all fixtures that exercise the changed contract and its affected callers.
For example, a change to HTTP/1 chunk terminators split across reads affects
the decoder, HttpClient response handling and HttpServer request handling.
Run the decoder fixture and both node fixtures together.

```bash
cmake --preset linux-unit-tests
ctest --preset linux-unit-debug --output-on-failure --no-tests=error \
  -R '^waterwall\.(http_chunk_decoder|http(client|server)_chunked_terminator)_unit$'
```

Use `ctest --preset linux-unit-debug -N -R 'http.*chunk'` to list matching
registrations. Debug enables assertions. Use `linux-unit-release` for optimized
or `NDEBUG` behavior. When both configurations exercise distinct affected paths,
run the relevant cases in each.

Stop once the selected tests pass and cover the affected paths. Reserve complete
local suites for an explicit request or a concrete risk that narrower checks
cannot cover. Linux CI runs the full Debug and Release suites.

Focused native CTest auto-builds each selected fixture's target through
[run_unit_test.cmake](run_unit_test.cmake), using the accepted per-tree lock and
bounded lock/build/child waits. Runs use private CWDs under
`<build>/test-runs/<configuration>/<test-name>/<invocation>/`; source/fixture
roots are explicit inputs. Build and executable diagnostics remain separate.
Failure/interruption/timeout/initialized skip retains artifacts; success removes
them unless `WATERWALL_TEST_KEEP_RUN_DIR=1`. Keep the production LTO tree separate
and do not build units there. Platform configurations use
`waterwall_platform_unit_tests`; cross-compilation proves building, not execution.

For a new unit, use [base64](base/base64_test.c) for small ordered cases,
[atomic_u32](base/atomic_u32_test.c) for portable/thread variants, or
[HeaderServer Est](tunnels/header/headerserver_est_ordering_test.c) for explicit
fixture composition. Link `ww_test_support` privately only when used. Its
requirements stay active under `NDEBUG`, evaluate operands once, and keep one
case context per executable. Publish a static case name before admitting work
and leave it unchanged until all workers/callbacks quiesce. `TEST_CHECK` reports
and returns a Boolean for existing accumulating/sentinel-return suites; those
callers retain their own continuation and final status. Deliberate product
assert/death tests keep their original sentinel, exit/signal and subprocess rules.
Standalone compile/link probes keep their dependency boundary.

Register sources explicitly with the [shared creation/registration helpers](../cmake/TestHelpers.cmake).
Keep source substitutions, wrapper symbols, feature definitions, Unity/PCH
exclusions and real `WW_HAVE_SPLICE=0` implementation builds visible beside the
target. Ordered drivers keep setup, stimulus, observations and successful
teardown in ordinary source. The worker driver keeps its initial fork cases
before shared initialization and live pipe/HalfDuplex/pool/batch cases before
teardown races. Final accessor death checks run after shared shutdown; the
`--line-refcount-publication-only` selection remains independent.

Format changed C/header ranges with portable `clang-format --style=file`.
[Developer Guide Part 6](https://github.com/radkesvat/WaterWall-Docs/blob/main/docs/05-devguides/part6-build-test-review.mdx)
is canonical for validation scope, sanitizer commands and lane timings.
