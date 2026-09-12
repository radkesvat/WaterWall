# Windows launcher fixture

This independent CMake project compiles the product launcher/backend, startup
handoff and decoder. A small ordinary PE exercises CRT/TLS initialization, exact
snapshot receipt, original location, companion DLL imports and exit status.
The smoke case checks companions beside the executable, executable-directory
precedence over CWD, and CWD-only deployment through the native loader.
It is not a second loader implementation or a full runtime replacement.

On Linux with MinGW x64 and Wine, from this directory:

```sh
cmake --preset mingw-x64
cmake --build --preset mingw-release -j8
ctest --preset mingw-release --output-on-failure
cmake --build --preset mingw-debug -j8
ctest --preset mingw-debug --output-on-failure
```

For a PE32 build-only check with an installed i686 MinGW compiler, use
`mingw-x86`, `mingw-x86-release`, and `mingw-x86-debug`. This preset does not
assume Wine32 is installed; execute its fixtures on native Windows.

On Windows, open the chosen native compiler environment, then use `native`,
`native-release` and `native-debug`. Tests retain the application and launcher
administrator manifests. Use an elevated test environment for unattended native
CTest execution; native interactive UAC still needs manual validation.

The native `waterwall.windows_lifecycle_launcher_fixture` exercises the public
interface without a client Job: graceful stop, forced launcher exit, controller
loss, already-dead controller rejection, and recovery. It also checks visible
startup with absent output streams and redirected configuration stdin, creation
failure before resume, and recovery's distinction between an orderly return and
abrupt runtime termination with the same full DWORD status. Recovery cases also
cover settled abrupt exit, retained driver-file residue, incomplete adapter
identity, and forced launcher death after recovery opens containment. The creation-failure
seam is compiled only into this small fixture's launcher. `windows_session_effects_test`
checks shared creation-intent publication, identity-resolution failure, bounded
inventory admission. These tests do not establish
native driver or OS-version qualification. See [the public lifecycle contract](LIFECYCLE.md)
and [the Python client examples](client.py). [Validation evidence and open
qualification items](LIFECYCLE-VALIDATION.md) identify the current artifact.
The contract's [forced-termination section](LIFECYCLE.md#what-remains-after-forced-termination)
separates process and packet-session teardown from adapter removal and persistent
file/device residue. An unverified recovery result is not evidence of surviving
traffic or physical-adapter DNS changes.

The separate full application cross-check is `windows-cross-mingw-x64` at the
repository root. It uses native GNU make and NASM for dependency builds, a native
host encoder and target MinGW compiler/tools. The ordinary application's runtime
and fixed-base policies remain intact. To compare whole-application startup and
the existing in-process worker/TLS workload:

```sh
python3 tests/windows_packed_application_test.py \
  --launcher build/windows-cross-mingw-x64/Release/Waterwall.exe \
  --application build/windows-cross-mingw-x64/Release/waterwall_application.exe \
  --wine wine
```

Run the optional `--tcp-loopback` workload only inside the existing Linux network
namespace harness (Wine) or a controlled native test runner; its existing fixture
uses a fixed loopback port. Wine cannot establish native IOCP, UAC, ACL/locking,
console events, antivirus, Windows Firewall or service-wrapper acceptance.

For build graph checks, use `tests/packed_build_target_test.py --windows` in an
idle configured tree, adding `--runner wine` when needed. The fixture is too small
to establish the full application's size reduction: compare the final launcher
against its matched finalized embedded application instead.

Windows x86/x64 CI uploads the packed `Waterwall.exe` under the existing artifact
names after the bootstrap checks and full application comparison pass. ARM64
remains ordinary; development presets retain their defaults. The launcher uses
temporary extraction and a separate child process. Read Developer Guide Parts 6
and 7 for deployment and lifetime limitations, including local ACL-capable
temporary storage, incompatible jobs,
forced termination, and path-based firewall rules.

For the isolated full-runtime lifecycle unit on Linux/MinGW (no LTO), use the root
`windows-cross-mingw-x64-unit` configure preset and
`windows-lifecycle-unit-debug` / `windows-lifecycle-unit-release` build presets.
Run `windows_lifecycle_test.exe` from that tree explicitly with Wine. This is a
diagnostic cross-check, not native Windows qualification; ordinary Windows unit
presets remain the native test path.

The same native client can exercise a complete packed artifact with a supplied
configuration:

```powershell
windows_lifecycle_launcher_test.exe --production C:\path\Waterwall.exe C:\private\core.json
```

Use absolute node paths in that configuration. This mode verifies real readiness,
graceful stop, controller loss, and pre-signaled controller rejection; it leaves
caller-owned config/log files intact. The ordinary fixture owns forced-crash cases
with its known small runtime. Full driver crash tests remain native qualification.
