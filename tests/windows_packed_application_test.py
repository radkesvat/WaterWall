"""Compare ordinary and packed Windows startup and an existing worker/TLS case.

The TLS case is entirely in-process. Optional TCP coverage reuses the namespace
harness's fixed loopback workload and requires an isolated/controlled runner.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--launcher', type=Path, required=True)
parser.add_argument('--application', type=Path, required=True)
parser.add_argument('--wine')
parser.add_argument('--tcp-loopback', action='store_true')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
binaries = [args.application.resolve(), args.launcher.resolve()]
prefix = [args.wine] if args.wine else []
env = os.environ.copy()
env['WINEDEBUG'] = '-all'
payload_source = binaries[1].parent.parent / 'packed' / binaries[1].parent.name / 'payload.c'
metadata = re.search(r'waterwallRuntimeLength = ([0-9]+)ULL', payload_source.read_text(encoding='ascii'))
assert metadata is not None and binaries[1].stat().st_size < int(metadata[1]), 'packing did not reduce finalized size'


with tempfile.TemporaryDirectory(prefix='Waterwall application comparison ') as temporary:
    root = Path(temporary)
    for arguments, data, status, marker in [
        (['--version'], b'', 0, b'Waterwall version'),
        (['-c:missing-core.json'], b'', 1, b'Could not open core settings file'),
        (['-c:stdin'], b'{}', 1, b'"configs" array'),
        (['--restricted-config', '-c:stdin'], b'{}', 1, b'"configs" array'),
        (['--restricted-config', '-c:stdin'], b'{}\0bad', 1, b'Restricted'),
    ]:
        results = []
        for binary in binaries:
            result = subprocess.run(prefix+[str(binary)]+arguments, input=data, cwd=root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=30)
            assert result.returncode == status, (binary, result.returncode, result.stdout, result.stderr)
            assert marker in result.stdout + result.stderr, (binary, result.stdout, result.stderr)
            results.append((result.stdout, result.stderr))
        assert results[0] == results[1], results

    cases = ['tls_roundtrip'] + (['tcp_loopback'] if args.tcp_loopback else [])
    for binary in binaries:
        for case in cases:
            run = root / (binary.name + '-' + case)
            shutil.copytree(repo/'tests/cases'/case, run)
            core = {'log': {'path': 'log/'}, 'configs': ['config.json'],
                    'misc': {'workers': 4, 'ram-profile': 'client', 'mtu': 1500, 'try-enabling-bbr': False}}
            (run/'core.json').write_text(json.dumps(core), encoding='utf-8')
            result = subprocess.run(prefix+[str(binary)], cwd=run, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
            logs = b'\n'.join(path.read_bytes() for path in (run/'log').glob('*.log'))
            assert result.returncode == 0 and b'worker lines completed successfully' in logs, (
                binary, case, result.returncode, result.stdout[-4000:], logs[-4000:])
    print('Ordinary/packed startup, settings rejection, worker/TLS and orderly exit passed')
