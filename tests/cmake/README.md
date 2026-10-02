# Test registration and execution

[TestHelpers.cmake](TestHelpers.cmake) captures absolute test/unit/support roots
at its definition site. Included fragments do not change
`CMAKE_CURRENT_SOURCE_DIR`. Both the Linux subtree and root platform entries
use the same functions; registration remains explicit CMake, with no source
wildcards or second registry.

`waterwall_add_native_executable` accepts explicit `SOURCES`, optional private
`INCLUDES`, `LIBRARIES`, `DEFINITIONS`, `EXCLUDE_FROM_ALL`, and opt-in `SUPPORT`.
`waterwall_register_native_test` registers an existing target with labels,
an optional execution `TIMEOUT` (default 120 seconds), selected `AGGREGATE`,
and `SOURCE_DIR` (default `CMAKE_SOURCE_DIR`). Standalone fixture projects pass
the repository root explicitly when their project root differs. The fixture
input root remains the captured native-test root. `waterwall_native_aggregate`
attaches a target once. The established `add_waterwall_unit_test` positional
interface selects the Linux aggregate. Portable/platform entries choose their
existing aggregate explicitly. Ordinary creation does not hide special build
properties: keep linker wraps, implementation substitutions, no-splice
variants, PCH/Unity exclusions, sanitizer flags and dependencies beside targets.

`native/` holds subsystem/family registrations, included in dependency order by
[unittests/CMakeLists.txt](../unittests/CMakeLists.txt). Root-only registrations
live in `native/platform.cmake`. Public portable/Windows and hard-abort entry
files remain under `unittests/` for their existing callers. `integration/`
holds explicit case families and [Helpers.cmake](integration/Helpers.cmake),
which retain namespace, prerequisite, marker and serial benchmark policies.
[tests/CMakeLists.txt](../CMakeLists.txt) owns configuration and includes.

[NativeRun.cmake](NativeRun.cmake) owns portable build/run locking, distinct
build/child capture, private CWDs and failure retention. The public native
runner and special abort/DNS controllers compose that boundary without nested
lock acquisition. Do not replace the exact-exit abort verdict with a signal or
turn missing prerequisites into success.

Use `ctest --preset linux --show-only=json-v1` and the two native-unit presets
to inspect actual registration names, commands, labels, timeouts and locks.
The [main workflow](../README.md) and [support contracts](../support/README.md)
explain authoring and execution.
