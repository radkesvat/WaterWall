"""Run the real launcher backend against a native-loader fixture, without a shell."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--launcher', required=True)
parser.add_argument('--application', required=True)
parser.add_argument('--wine')
args = parser.parse_args()
env = os.environ.copy()
env['WINEDEBUG'] = '-all'
prefix = [args.wine] if args.wine else []

with tempfile.TemporaryDirectory(prefix='Waterwall fixture spaces ') as temporary:
    root = Path(temporary)
    folder = 'deployment with spaces'
    if args.wine:
        folder = 'déployment with spaces'
    elif os.name == 'nt':
        try:
            'é'.encode('mbcs', errors='strict')
            folder = 'déployment with spaces'
        except UnicodeError:
            pass
    deployment = root / folder
    deployment.mkdir()
    for source in Path(args.launcher).parent.glob('*.dll'):
        shutil.copyfile(source, deployment / source.name)
    launcher = deployment / 'Waterwall.exe'
    application = deployment / 'ordinary.exe'
    shutil.copyfile(args.launcher, launcher)
    shutil.copyfile(args.application, application)
    unrelated = root / 'unrelated'
    unrelated.mkdir()
    extraction = root / 'extraction'
    extraction.mkdir()
    def windows_path(path):
        return 'Z:' + str(path).replace('/', '\\') if args.wine else str(path)
    env['TEMP'] = env['TMP'] = windows_path(extraction)
    env['WW_FIXTURE_ORIGINAL'] = windows_path(launcher)

    def run(binary, arguments, data=b'{}', extra=None):
        run_env = env.copy()
        run_env.pop('WW_CORE_JSON_INPUT', None)
        run_env.update(extra or {})
        report = root / ('image-' + uuid.uuid4().hex)
        if binary == launcher:
            run_env['WW_FIXTURE_IMAGE_REPORT'] = windows_path(report)
        result = subprocess.run(prefix + [str(binary)] + arguments, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=unrelated, env=run_env, timeout=15)
        if binary == launcher and b'snapshot:' in result.stdout:
            assert report.exists(), 'child image path report missing'
            image = report.read_bytes().decode('utf-16-le')
            report.unlink()
            if args.wine:
                image = subprocess.check_output(['winepath', '-u', image], env=run_env, timeout=15).decode().strip()
            extracted = Path(image)
            assert not extracted.exists() and not extracted.parent.exists(), ('owned residue', image)
        return result.returncode, result.stdout.replace(b'\r\n', b'\n'), result.stderr.replace(b'\r\n', b'\n')

    for option in ('--version', '-v', 'version'):
        code, out, err = run(launcher, [option])
        assert code == 0 and b'Waterwall version' in out, (code, out, err)
    for options, data in [(['--ww-internal-map=4'], b'{}'), (['unknown'], b'{}'),
                          (['-c:missing.json'], b'{}'), (['-c:stdin'], b'['),
                          (['--restricted-config', '-c:stdin'], b'{}\0bad')]:
        code, out, err = run(launcher, options, data)
        assert code != 0 and b'snapshot:' not in out, (code, out, err)
        assert not list(extraction.iterdir()), list(extraction.iterdir())

    # Wine substitutes its own TEMP for an invalid directory before our process
    # starts. Native Windows preserves it, exercising this extraction failure.
    if not args.wine:
        invalid_root = windows_path(root / 'missing extraction root')
        code, out, err = run(launcher, ['-c:stdin'], extra={'TEMP': invalid_root, 'TMP': invalid_root})
        assert code != 0 and b'snapshot:' not in out and b'Packed runtime:' in err, (code, out, err)
        assert not list(extraction.iterdir()), list(extraction.iterdir())

    def compare(data, restricted=False, extra=None):
        options = ['-c:stdin'] + (['--restricted-config'] if restricted else [])
        ordinary = run(application, options, data, extra)
        packed = run(launcher, options, data, extra)
        assert ordinary == packed, (ordinary, packed)
        assert b'snapshot:' in packed[1], packed
        expected = int((extra or {}).get('WW_FIXTURE_EXIT', '0'), 0)
        assert packed[0] & 0xffffffff == expected & (255 if args.wine else 0xffffffff), packed

    for data in (b'{}', b'{"x":1}\r\n', b'{}\x1aafter', b'{}\0after',
                 b'\xef\xbb\xbf{}', b'{"x":"' + b'a' * (1024*1024) + b'"}'):
        compare(data)
    for data in (b'{}', b'{"x":1}\r\n', b'{"x":"' + b'a'*65536 + b'"}'):
        compare(data, True)
    for status in ('7', '0x80000001', '0xc0000005'):
        compare(b'{}', extra={'WW_FIXTURE_EXIT': status})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(compare, [b'{}']*4))
    assert not list(extraction.iterdir()), list(extraction.iterdir())
    for options, extra in [([], {'WW_CORE_JSON_INPUT': 'stdin'}),
                           (['-c:stdin'], {'WW_CORE_JSON_INPUT': 'missing-core.json'})]:
        ordinary = run(application, options, b'{}', extra)
        packed = run(launcher, options, b'{}', extra)
        assert ordinary == packed and b'snapshot:' in packed[1], (ordinary, packed)
    (unrelated / 'core.json').write_bytes(b'{"default":true}')
    assert run(application, []) == run(launcher, [])
    config = unrelated / 'configuration with spaces.json'
    config.write_bytes(b'{"file":true}')
    for alias in ('-c:', '--c:', '-config:', '--config:', 'config:'):
        ordinary = run(application, [alias + windows_path(config)])
        packed = run(launcher, [alias + windows_path(config)])
        assert ordinary == packed, (ordinary, packed)
    expected = run(application, ['-c:' + windows_path(config)])
    captured = run(launcher, ['-c:' + windows_path(config)], extra={'WW_FIXTURE_REMOVE_SOURCE': '1'})
    assert captured == expected and not config.exists(), (captured, expected)
    # The executable directory precedes CWD, but CWD remains a fallback when
    # there is no adjacent companion. Exercise the native implicit-import path.
    companions = list(deployment.glob('*.dll'))
    assert companions, 'fixture companion DLL missing'
    for companion in companions:
        (unrelated / companion.name).write_bytes(b'not a PE DLL')
    compare(b'{}')
    for companion in companions:
        companion.replace(unrelated / companion.name)
    compare(b'{}')
    assert not list(extraction.iterdir()), list(extraction.iterdir())
    print('Windows launcher fixture: startup, exact snapshots, DLL, TLS, exits, concurrent cleanup passed')
