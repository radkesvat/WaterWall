#!/usr/bin/env python3
"""Check the public packed target in a configured, otherwise idle build tree.

Run separately from CTest/build jobs: this temporarily removes a generated
launcher and touches the private executable. User sources are never modified.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--config', choices=('Debug', 'Release'), required=True)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--cmake', default='cmake')
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    cache = (build_dir / 'CMakeCache.txt').read_text()
    if 'WW_PACK_RUNTIME:BOOL=ON' not in cache:
        parser.error('requires a configured packed build tree')
    launcher = build_dir / args.config / 'Waterwall'
    application = launcher.with_name('waterwall_application')
    payload = build_dir / 'packed' / args.config / 'payload.c'

    def build():
        subprocess.run([args.cmake, '--build', str(build_dir), '--config', args.config,
                        '--target', 'Waterwall', '-j', str(args.jobs)], check=True)

    build()
    if not all(path.is_file() for path in (launcher, application, payload)):
        raise AssertionError('public target did not produce the complete packed executable')
    with tempfile.TemporaryDirectory(prefix='public-target-', dir=build_dir) as temporary:
        saved = Path(temporary) / 'Waterwall'
        launcher.rename(saved)
        recreated = False
        try:
            build()
            if not launcher.is_file():
                raise AssertionError('public target did not recreate the missing launcher')
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
    settled = payload.stat().st_mtime_ns
    build()
    if payload.stat().st_mtime_ns != settled:
        raise AssertionError('unchanged public target unnecessarily regenerated the payload')
    subprocess.run([str(launcher), '--version'], check=True)
    print(f'Public Waterwall target: {args.config} checks passed')


if __name__ == '__main__':
    main()
