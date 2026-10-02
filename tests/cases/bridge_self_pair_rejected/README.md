# Bridge self pair rejected


Exercises the bridge self pair rejected scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `bridge-a`: `Bridge` paired with `bridge-a`

CTest selections and overrides:

- `waterwall.bridge_self_pair_rejected` — default runner settings.

Prerequisites: The production build and Linux user/network namespace support. Loopback endpoints live inside the namespace harness.

Success: The runtime must exit with status `1` and include the diagnostic `Bridge: pair node "bridge-a" must name a distinct Bridge node`. Signals, hard aborts, and missing or different diagnostics fail; the accepted expected failure counts as a successful enclosing test.

Discover properties with `ctest --preset linux -N -V -R '^waterwall\.bridge_self_pair_rejected$'`. Execute through the [lane wrapper](../../run_test_lane.sh) using the registered lane; privileged/external and speed cases keep their own prerequisites/serialization.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
