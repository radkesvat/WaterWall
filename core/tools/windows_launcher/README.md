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

The native `waterwall.windows_hosted_launcher_fixture` test uses the same packed
launcher and PE fixture with `--hosted`, `--host-stop-event:<decimal handle>` and
optional `--host-ready-event:<decimal handle>`. It checks enclosing Job policy,
same-Job runtime membership, hidden runtime creation, least event rights,
optional readiness, pre-signaled stop, full DWORD exit status, last-host-Job-handle
closure, and launcher failure followed by host settlement of the runtime. It
retires forced-exit residue only after confirming process death. Missing-Job
rejection is explicitly reported as unverified if the test runner already belongs
to a Job. This fixture does not qualify runtime commit, exact cancellation races
during extraction/admission, OS-version coverage, or a service-specific token.

Hosted mode does not retain a host Job handle or create a second Job. The host
must assign the suspended launcher to a kill-on-close Job with neither breakaway
flag, create manual-reset lifecycle events, enforce its startup/stop deadlines,
and settle the complete Job before retiring session files. Only the runtime
signals readiness; omitting the readiness event leaves readiness determination
to the host. Standalone invocation retains its private Job and console behavior.
Do not assume that the Job contains exactly two processes: Windows console
infrastructure can also appear as members despite `CREATE_NO_WINDOW`.

Use the same native host against a complete production packed artifact:

```powershell
build/windows-launcher-native/Debug/windows_hosted_launcher_test.exe --production build/local-vs2022/Debug/Waterwall.exe
```

Pass an absolute artifact path when running from another directory. Production
mode supplies an in-process `TesterClient -> BlackHole` configuration with restricted parsing,
waits for the runtime's real readiness event, requests orderly stop, and verifies
zero exit status and whole-Job settlement. It also exercises intentional omission
of readiness and pre-signaled cancellation. The no-readiness case observes
process survival only; it does not claim a runtime readiness milestone. This
mode creates no listeners or driver nodes and does not use console diagnostics
as a readiness protocol.

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
