# Shared test support

These helpers are private to tests. Scenario inputs, callback actions, expected
results, deadlines, feature branches and setup/teardown stay in each test.

## C requirements and cases

Include `test_assert.h` and link `ww_test_support` **privately**, or select
`SUPPORT` when creating a target with `waterwall_add_native_executable`. The target is
created before both Linux and portable registrations, disables PCH and IPO, and
has no dependency on `ww`, threads or linker wrappers. Its header also compiles
as C++. It follows the existing Debug-only sanitizer options.

For runtime fixtures, include the WaterWall header before `test_assert.h` in a
separate include group. WaterWall establishes feature macros before system
headers; the separate group preserves that dependency during include sorting.

`TEST_REQUIRE` checks a boolean with an explanatory message. `TEST_EQUAL_INT`,
`TEST_EQUAL_UINT`, `TEST_EQUAL_SIZE`, `TEST_EQUAL_POINTER`, `TEST_EQUAL_TEXT` and
`TEST_EQUAL_BYTES` report expected and actual values. Every operand is evaluated
once; their relative evaluation order is unspecified. Keep dependent operations
in separate statements or an existing short-circuit boolean check. Byte checks
report the first mismatch and at most eight bytes from each input. Text and byte
operands must meet the preconditions documented in the header.

Pass `TEST_FAILURE_EXIT` for `exit(1)` or `TEST_FAILURE_QUICK_EXIT` for `_Exit(1)`.
Choose the existing test's policy explicitly. `TEST_CHECK(condition, message)`
reports a failure and returns the condition without exiting. Use it when the suite
must accumulate failures, return its own status, call `abort()`, or retain a
platform exit such as `ExitProcess`; the suite still decides continuation and its
final verdict. Requirements are active under
`NDEBUG`; they do not replace production contract assertions or their death
tests, invoke runtime shutdown, or perform fixture cleanup.

Use `TEST_RUN_CASE(function)` in the desired order in `main`. Parameterized cases
use `testCaseSet("name")` before the visible call. One context is shared across
translation units. Names have static storage and must remain stable from before
thread/callback admission until all case work has joined or quiesced. Never
change a name from a live callback or worker. Custom setup and successful
teardown remain explicit. See [base64](../unittests/base/base64_test.c) and
[atomic_u32](../unittests/base/atomic_u32_test.c).

The pure library is defined in [c/CMakeLists.txt](c/CMakeLists.txt), so a standalone
platform fixture can import it without adding runtime dependencies or registering
the support regression suite. Compile/link probes that test an independent
archive or public-header boundary retain that boundary instead of linking support.

## Runtime fixtures

[tunnel_line_failure_harness.h](c/fixtures/failure/tunnel_line_failure_harness.h) is
the `twf*` composition entry point. Its assertions use the shared case and
`_Exit(1)` policy. The explicit pieces under `c/fixtures/` are:

- `assertions.h`: `twf*` reporting adapters, preserving uint32 argument conversion.
- `process_guard.h`: opt-in Category-C process wrappers. Define
  `TWF_CUSTOM_PROCESS_API_WRAPS` before inclusion to provide the orderly-shutdown
  harness's recording guards instead.
- `buffer_ledger.h`: opt-in buffer wrappers and the existing acquisition/recycle
  ledger. Link all declared GNU wrapper symbols; include in one fixture TU.
- `callback_trace.h`: next/upstream and prev/downstream mock observation. Its
  Finish recorder does not own or destroy a line.
- `worker_lines.h`: worker-zero GSTATE/pool/event-loop setup, bare normal-line and
  pool-backed normal-line fixtures, and owner Finish postconditions. It uses the
  buffer ledger. Scenarios own line closure, held references and visible teardown.

Include only the needed pieces. Simple codec/atomic tests must not inherit
runtime guards. [HeaderServer](../unittests/tunnels/header/headerserver_est_ordering_test.c) uses
[protocol_est_ordering_fixture.h](c/fixtures/protocols/protocol_est_ordering_fixture.h):
the previous mock owns the normal line, the transform/next borrow it, and a held
observation reference enables teardown checks after logical death. Keep buffer
ownership, callback direction, WID context and pool teardown ordering explicit.

The `failure/` directory also owns the orderly-shutdown composition and the
one-TU buffer-disposal probe. `protocols/` owns shared Est-ordering, fallback,
HalfDuplex and UDP splice fixtures; `lwip/` owns raw-stack runtime setup.
[worker_registry_fixture.h](c/fixtures/worker_registry_fixture.h) installs only
the checked worker registry needed by small component tests. Each header documents
which wrapper symbols and teardown it requires. Shared mechanics belong here;
family-specific parser state and expected callback sequences stay with the suite.

The [worker suite driver](../unittests/net/worker/worker_context_helpers_test.c)
uses a suite-local runtime fixture and separate accessor, message, pipe,
HalfDuplex and teardown case modules. Its explicit order preserves the forked
initial cases before shared initialization and live cases before workers 1–8
close admission. Final accessor death checks run after shared shutdown. This
fixture is not a replacement for the smaller shared helpers.

## Python helpers

Before importing, set `sys.dont_write_bytecode = True` and insert
`Path(__file__).resolve().parent / "support" / "python"` into `sys.path` for an
entry under `tests/`. Case probes resolve the mirrored tests root two parents
above their file. Owners of arbitrary copied directories, including Windows
examples, pass `WATERWALL_TEST_SUPPORT_DIR` explicitly. There is no installation
or import dependency on CWD. See [HalfDuplex](../halfduplex_splice_integration.py).
Consumers import helpers directly from support; CLI entry paths stay stable.

- `wwtest.sockets.exact(sock, size)`: exact bytes with partial-progress EOF and
  timeout diagnostics. Probe adapters can preserve raw timeouts, EOF returning
  `None`, their original exception factory, and a capped receive size explicitly.
  `configure_listener` configures an existing socket; `connect_when_ready` returns
  the actual scenario connection with the caller's absolute deadline. Keep UDP
  publication and other retry/readiness policies explicit.
- `wwtest.trace.successful_calls(trace)`: positive strace transfers, including
  per-thread unfinished/resumed joins. Endpoint interpretation stays in the test.
- `wwtest.run_directory.RunDirectory(prefix, parent=None)`: generate inputs/logs
  privately; announce the path on creation; retain exceptions, initialized skips
  and timeouts. Success removes it unless `WATERWALL_TEST_KEEP_RUN_DIR=1`.
- `wwtest.process.Process(command, cwd=..., log_path=...)`: POSIX child ownership,
  merged log capture, startup checks, explicit signals/exit results, bounded kill
  and reap. A private session settles a `strace -D` tracing group while retaining
  the runtime as the direct child. Detached tracers are reaped by their parent;
  group quiescence precedes log/trace consumption and directory deletion.
- `wwtest.config.core_config`: common four-logger settings. Callers retain their
  own node topology, misc/DNS values, config writes and scenario overrides.
- `wwtest.process.run_logged`: bounded `subprocess.run` with numbered command and
  complete captured-output receipts under the caller's private CWD. It does not
  dump environments or stdin. Existing Windows failure/replay receipts stay local.
  `stop_process` and `kill_and_reap` settle direct children on POSIX or Windows;
  Windows capability events and descendant tree handling remain explicit.
- `wwtest.process.close_on_error`: unblock a peer before executor joins while
  preserving the body exception and normal socket lifetime. Futures still have
  explicit result/deadline checks in their scenario. CLI scripts opt into
  `install_termination_handler` to unwind owned resources on outer SIGTERM.

Mains that catch failures and return statuses use `RunDirectory.create()` and
`finish(status)` explicitly, including initialized skip 77 and unconditional
benchmark retention. Resource settlement must precede `finish`. Success-retention
aliases already supported by specialized runners remain explicit at their caller.

Named fixtures under `wwtest.fixtures` share actual protocol/platform setup and
observations: HTTP proxy headers/endpoints, TLS ClientHello peeking, Reality wire
profiles, SNI routing peers, SocketManager marker servers and the real TUN TCP
namespace/byte-exchange fixture. Their modules document ownership and limits;
scenario expectations remain visible. The `source_policy` lexical scanner and
`packed_launcher` PE checks are shared read-only analysis, not test entry points.

## Shell helpers

Public runner and `case_run_dir.lib.sh` paths remain stable. The latter delegates
to `support/shell/run_directory.sh` for private mirrored inputs, source support
imports, retention and expected-failure receipt ownership. `runner.lib.sh` provides
ordered log dumps, stdout override, explicit-PID TERM/KILL/reap, simple directory
settlement and generated client core settings with caller-supplied values.

Callers own traps and capture the enclosing status before cleanup. Keep probe
before runtime settlement, numeric statuses and each marker/report/probe/speed
verdict in the public runner. Privileged preflight, hostile process-group fault
injection and benchmark workload/metric logic remain specialized. An accepted
expected failure removes both the runtime root and its enclosing capture; a
rejected verdict retains both. Cookie relay verification owns the final verdict
for its relay trace and underlying runtime root.

Use the directory as the outer context. Close sockets and join peer futures
before leaving the process context and directory. Descendants must remain in the
owned process group. Process cleanup retains the original scenario exception if
cleanup also fails. Keep prerequisite checks, readiness connections, strace
arguments, expected exits and scenario deadlines visible. A missing prerequisite
must remain a failure or explicit skip.

## Focused support checks

```bash
cmake --preset linux-unit-tests
cmake --build --preset linux-unit-debug --target base64_test atomic_u32_test headerserver_est_ordering_test test_support_regression -j8
ctest --preset linux-unit-debug --output-on-failure --no-tests=error -R '^waterwall\.(base64|atomic_u32|headerserver_est_ordering|test_support)_unit$'
cmake --build --preset linux-unit-release --target base64_test atomic_u32_test headerserver_est_ordering_test test_support_regression -j8
ctest --preset linux-unit-release --output-on-failure --no-tests=error -R '^waterwall\.(base64|atomic_u32|headerserver_est_ordering|test_support)_unit$'
cmake --preset linux
cmake --build --preset linux -j8
ctest --preset linux --output-on-failure --no-tests=error -R '^waterwall\.(python_test_support|halfduplex_tcp_splice_(true|false)|trojanclient_(tcp|udp)_splice_(true|false)|httpproxyserver_(noauth|local|tracked|fallback|blocked)_splice_(true|false))$'
```

`waterwall.test_support_unit` exercises NDEBUG requirements, operands, diagnostics
across two TUs and both failure policies through the existing native run boundary;
its target includes the C++ header compile check. The nonterminating check mode
verifies that the caller can continue and retain its chosen status.
`waterwall.python_test_support`
checks socket/trace semantics and artifact/process failure cleanup in the support
lane. Shared-fixture changes require full native Debug/Release suites; utility
provider changes require production support and functional lanes. Cross-builds
prove compilation/linking, not native platform execution.
