#!/usr/bin/env python3
"""Direct trusted pairs versus interposed TCP-UDP bridge checks in both offload modes, MTU1500/576, slow receiver, DNS
and real software-forwarded wire checksums. Fresh TUN/runtime/peer namespaces and four 1MiB
connections; explicit GSO counters and exact transport checks. Linux root/TUN/namespaces/ethtool;
missing capability is skip77. CTest: waterwall.tundevice_trusted_checksum."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.run_directory import RunDirectory
from wwtest.fixtures.tun_tcp import (Fixture, Unavailable, preflight, require, command, output, stop,
                           integration, TRANSFER, TUN, CLIENT, SERVER, PORT, SOURCE_PORT)

HELPER = Path(__file__).with_name('tun_checksum_transfer.py')
FORWARDED = '198.19.1.2'


class ChecksumFixture(Fixture):
    def __init__(self, binary, directory, gso, interposed, mtu=1500):
        super().__init__(binary, directory, gso)
        self.interposed = interposed
        self.mtu = mtu

    def configure(self, config):
        super().configure(config)
        config['nodes'][2]['type'] = 'TcpUdpConnector'
        config['nodes'][1]['settings']['fake-dns'] = {'cache-size': 64}
        config['nodes'][1]['settings']['mtu'] = self.mtu
        if self.interposed:
            config['nodes'][0]['next'] = 'middle'
            config['nodes'].append({'name': 'middle', 'type': 'IpOverrider', 'next': 'stack',
                                    'settings': {'chance': 0, 'up': {'source-ip': {'ipv4': CLIENT}}}})
        # Exercise PTC startup before TUN publication as well as the original order.
        config['nodes'][0], config['nodes'][1] = config['nodes'][1], config['nodes'][0]


def wait_ready(process, ready):
    deadline = time.monotonic() + 5
    while not ready.exists():
        require(process.poll() is None, 'helper exited before admission')
        require(time.monotonic() < deadline, 'helper readiness timeout')
        time.sleep(.02)


def udp_exchange(fixture, client, address, suffix):
    ready = fixture.directory / ('udp-ready-' + suffix)
    server = fixture.spawn([*fixture.peer, sys.executable, str(HELPER), 'server', '--bind', SERVER,
                            '--ready', str(ready)], 'udp-server-' + suffix + '.log')
    wait_ready(server, ready)
    result = command(*client, sys.executable, str(HELPER), 'client', '--bind', address, '--address', SERVER,
                     capture_output=True, timeout=30)
    server.wait(timeout=5)
    require(server.returncode == 0, 'UDP server failed')
    return json.loads(result.stdout)


def forwarding(fixture):
    client = fixture.namespace('forward-client')
    command(*fixture.runtime, 'ip', 'link', 'add', 'wwcsout', 'type', 'veth', 'peer', 'name', 'wwcspeer')
    command(*fixture.runtime, 'ip', 'link', 'set', 'wwcspeer', 'netns', client[2])
    command(*fixture.runtime, 'ip', 'addr', 'add', '198.19.1.1/24', 'dev', 'wwcsout')
    command(*fixture.runtime, 'ip', 'link', 'set', 'wwcsout', 'up')
    command(*client, 'ip', 'addr', 'add', FORWARDED + '/24', 'dev', 'wwcspeer')
    command(*client, 'ip', 'link', 'set', 'wwcspeer', 'up')
    command(*client, 'ip', 'route', 'add', SERVER + '/32', 'via', '198.19.1.1')
    command(*fixture.runtime, sys.executable, '-c',
            "from pathlib import Path; Path('/proc/sys/net/ipv4/ip_forward').write_text('1\\n')")
    # Force software completion in the namespace egress. Inspect actual features;
    # a virtual-interface roundtrip retaining CHECKSUM_PARTIAL is insufficient.
    command(*fixture.runtime, 'ethtool', '-K', 'wwcsout', 'tx', 'off', 'tso', 'off', 'gso', 'off')
    command(*client, 'ethtool', '-K', 'wwcspeer', 'gro', 'off', 'lro', 'off')
    features = output(*fixture.runtime, 'ethtool', '-k', 'wwcsout')
    for feature in ('tx-checksumming', 'tcp-segmentation-offload', 'generic-segmentation-offload'):
        require(feature + ': off' in features, 'egress still supports ' + feature)
    (fixture.directory / 'software-egress-features.txt').write_text(features)
    ready = fixture.directory / 'capture-ready'
    capture = fixture.spawn([*client, sys.executable, str(HELPER), 'capture', '--bind', FORWARDED,
                             '--interface', 'wwcspeer', '--ready', str(ready)], 'wire-capture.json')
    wait_ready(capture, ready)
    common = ['--address', SERVER, '--port', str(PORT), '--connections', '4', '--bytes', '1048576']
    server = fixture.spawn([*fixture.peer, sys.executable, str(TRANSFER), 'server', *common], 'forward-server.log')
    fixture.wait_server(server)
    command(*client, sys.executable, str(TRANSFER), 'client', *common, '--bind', FORWARDED,
            '--source-port', str(SOURCE_PORT), capture_output=True, timeout=35)
    server.wait(timeout=5)
    require(server.returncode == 0, 'forwarding TCP server failed')
    udp_exchange(fixture, client, FORWARDED, 'forward')
    stop(capture)
    require(capture.returncode == 0, 'independent wire checksum verification failed')
    return json.loads((fixture.directory / 'wire-capture.json').read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    directory = None
    run_directory = None
    success = False
    try:
        preflight('integration')
        if shutil.which('ethtool') is None:
            raise Unavailable('software forwarding qualification requires ethtool')
        run_directory = RunDirectory('waterwall-tun-checksum-')
        directory = run_directory.create()
        print('Artifacts: ' + str(directory), flush=True)
        for gso, interposed, mtu in ((False, False, 1500), (False, True, 1500), (False, False, 576),
                                    (True, True, 1500), (True, False, 1500), (True, False, 576)):
            name = ('gso-' if gso else 'checksum-') + ('interposed' if interposed else 'trusted')
            if mtu != 1500:
                name += '-mtu' + str(mtu)
            with ChecksumFixture(args.binary.resolve(), directory / name, gso, interposed, mtu) as fixture:
                # Four concurrent 1 MiB uploads at MTU 576 can burst nearly
                # 8,000 TCP packets. The default 500-entry TUN queue drops them
                # and loss recovery can exceed the transfer's 30-second deadline.
                command(*fixture.runtime, 'ip', 'link', 'set', 'dev', TUN, 'txqueuelen', '16384')
                log = (fixture.directory / 'waterwall.log').read_text()
                active = 'enabled direct-pair trusted transport checksums' in log
                require(active == (fixture.checksum_enabled and not interposed), 'incorrect pair activation')
                integration(fixture)
                udp_exchange(fixture, fixture.runtime, CLIENT, 'local')
                command(*fixture.runtime, sys.executable, str(HELPER), 'dns', '--bind', CLIENT,
                        '--address', SERVER, timeout=10)
                # The 32-question reply exceeds MTU 576 and must have its full
                # UDP checksum before the real IP fragmentation/kernel path.
                command(*fixture.runtime, sys.executable, str(HELPER), 'dns', '--bind', CLIENT,
                        '--address', SERVER, '--questions', '32', timeout=10)
                if active and mtu == 1500:
                    common = ['--address', SERVER, '--port', str(PORT), '--connections', '4',
                              '--bytes', '1048576', '--receive-delay', '.02']
                    server = fixture.spawn([*fixture.peer, sys.executable, str(TRANSFER), 'server', *common],
                                           'slow-server.log')
                    fixture.wait_server(server)
                    # Keep this independent scenario out of the preceding
                    # transfer's still-closing TCP tuples.
                    command(*fixture.runtime, sys.executable, str(TRANSFER), 'client', *common, '--bind', CLIENT,
                            '--source-port', str(SOURCE_PORT + 100), capture_output=True, timeout=35)
                    server.wait(timeout=5)
                    require(server.returncode == 0, 'slow receiver exchange failed')
                result = forwarding(fixture) if mtu == 1500 else {}
                result['offload'] = fixture.finish()
                print(name + ': ' + json.dumps(result), flush=True)
        success = True
        return 0
    except Unavailable as error:
        print('SKIP: ' + str(error), flush=True)
        return 77
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('FAIL: ' + str(error), file=sys.stderr, flush=True)
        return 1
    finally:
        if run_directory is not None:
            run_directory.finish(0 if success else 1)


if __name__ == '__main__':
    sys.exit(main())
