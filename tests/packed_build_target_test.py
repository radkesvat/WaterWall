#!/usr/bin/env python3
"""Check the public packed target in a configured, otherwise idle build tree.

Run separately from CTest/build jobs: this temporarily removes a generated
launcher and touches the private executable. User sources are never modified.
"""
import argparse
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', choices=('Debug', 'Release'), required=True)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--cmake', default='cmake')
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--windows', action='store_true')
    parser.add_argument('--runner', nargs='+', default=[])
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    cache = (build_dir / 'CMakeCache.txt').read_text()
    if not re.search(r'^WW_PACK_RUNTIME:BOOL=(ON|TRUE|YES|Y|1)$', cache, re.M | re.I) and 'WaterwallWindowsLauncherFixture' not in cache:
        parser.error('requires a configured packed build tree')
    suffix = '.exe' if args.windows else ''
    launcher = build_dir / args.config / ('Waterwall' + suffix)
    application = launcher.with_name('waterwall_application' + suffix)
    payload = build_dir / 'packed' / args.config / 'payload.c'

    def build():
        subprocess.run([args.cmake, '--build', str(build_dir), '--config', args.config,
                        '--target', 'Waterwall', '-j', str(args.jobs)], check=True)

    def check_stripped():
        if args.windows:
            data = launcher.read_bytes()
            pe = struct.unpack_from('<I', data, 60)[0]
            if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0':
                raise AssertionError('launcher is not PE')
            optional = pe + 24
            magic = struct.unpack_from('<H', data, optional)[0]
            directories = optional + (112 if magic == 0x20b else 96)
            flags = struct.unpack_from('<H', data, optional+70)[0]
            if flags & 0x140 != 0x140:
                raise AssertionError('launcher must retain ASLR and DEP')
            if not all(struct.unpack_from('<II', data, directories + 5*8)):
                raise AssertionError('launcher must retain base relocations')
            if any(struct.unpack_from('<II', data, directories + 6*8)):
                raise AssertionError('launcher still has an embedded debug directory')
            section_count = struct.unpack_from('<H', data, pe+6)[0]
            section_start = optional + struct.unpack_from('<H', data, pe+20)[0]
            for index in range(section_count):
                name = data[section_start+index*40:section_start+index*40+8]
                if name.startswith((b'.debug', b'.zdebug', b'.stab')):
                    raise AssertionError('launcher still has debug sections')
            if struct.unpack_from('<I', data, pe+16)[0] != 0:
                raise AssertionError('launcher still has COFF symbols')
            inner = application.read_bytes()
            inner_pe = struct.unpack_from('<I', inner, 60)[0]
            if struct.unpack_from('<H', inner, inner_pe+24+70)[0] & 0x60:
                raise AssertionError('application lost its non-ASLR policy')
            return
        sections = subprocess.check_output(
            [args.readelf, '--wide', '--sections', str(launcher)], text=True)
        if 'SYMTAB' in sections or re.search(r'\s\.(?:z?debug|stab)', sections):
            raise AssertionError('packed launcher still contains static symbols or debug information')

    build()
    if not all(path.is_file() for path in (launcher, application, payload)):
        raise AssertionError('public target did not produce the complete packed executable')
    check_stripped()
    with tempfile.TemporaryDirectory(prefix='public-target-', dir=build_dir) as temporary:
        saved = Path(temporary) / 'Waterwall'
        launcher.rename(saved)
        recreated = False
        try:
            build()
            if not launcher.is_file():
                raise AssertionError('public target did not recreate the missing launcher')
            check_stripped()
            recreated = True
        finally:
            # Preserve the previous deliverable if rebuilding fails or is interrupted.
            if not recreated:
                saved.replace(launcher)

    previous_payload = payload.stat().st_mtime_ns
    previous_launcher = launcher.stat().st_mtime_ns
    application.touch()
    build()
    if payload.stat().st_mtime_ns <= previous_payload:
        raise AssertionError('updating the application did not regenerate its payload')
    if launcher.stat().st_mtime_ns <= previous_launcher:
        raise AssertionError('updating the application did not relink the launcher')
    check_stripped()
    settled = payload.stat().st_mtime_ns
    build()
    if payload.stat().st_mtime_ns != settled:
        raise AssertionError('unchanged public target unnecessarily regenerated the payload')
    subprocess.run(args.runner + [str(launcher), '--version'], check=True)
    print(f'Public Waterwall target: {args.config} checks passed')


if __name__ == '__main__':
    main()
