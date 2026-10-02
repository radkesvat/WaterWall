#!/usr/bin/env python3
"""Public packed-target rebuild after removing a generated launcher and touching its private input,
finalized PE/ELF metadata and public version execution. Requires an otherwise idle configured build
tree; temporarily mutates only generated products. Not a concurrent CTest workload. CTest: direct
CLI/support fixture; called by the registered owning suite."""
import sys
import os
import argparse
from pathlib import Path
import re
import struct
import subprocess

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.run_directory import RunDirectory
from wwtest.packed_launcher import check_windows_launcher




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
            check_windows_launcher(launcher.read_bytes())
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
    with RunDirectory(prefix='public-target-', parent=build_dir) as temporary:
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
