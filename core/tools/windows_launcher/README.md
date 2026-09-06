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

Windows release downloads remain ordinary until native application and manual
acceptance are recorded. The launcher uses temporary extraction and a separate
child process. Read Developer Guide Parts 6 and 7 for deployment and lifetime
limitations, including local ACL-capable temporary storage, incompatible jobs,
forced termination, and path-based firewall rules.
