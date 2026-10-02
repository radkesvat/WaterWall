# Tundevice tcp chain


Exercises the tundevice tcp chain scenario with the topology in this directory.

Configured nodes and onward edges (`next`; listeners/connectors form the OS transport boundaries):

- `tun`: `TunDevice` → `stack`
- `stack`: `PacketsToConnection` → `out`
- `out`: `TcpConnector` (terminal or independently bound endpoint)

Scenario choices: `tun.device-mtu=1500`, `tun.gso=true`, `stack.mtu=1500`. These values define the workload/edge case and are not tuning advice.

Fixture input for [TUN TCP integration/speed](../../tun_tcp_chain.py) and [trusted-checksum validation](../../tun_trusted_checksum.py). Their named fixture requires private namespaces, TUN and its explicit tools/privileges; missing prerequisites skip. The TCP case verifies the complete echo bytes; speed retains the frozen iperf workload and metrics. Discover their selections with `ctest --preset linux -N -R tundevice`.

Generated core settings, logs and mutable inputs belong to the private run directory. Failures/skips retain initialized artifacts; `WATERWALL_TEST_KEEP_RUN_DIR=1` also retains success. See the [test workflow](../../README.md).
