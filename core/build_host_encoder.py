"""Serialize a native encoder build without inheriting target compiler flags."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess


@contextmanager
def build_lock(path):
    # Opening in append mode never truncates a lock another configuration owns.
    with path.open('a+b') as lock:
        if os.name == 'nt':
            import msvcrt
            if path.stat().st_size == 0:
                lock.write(b'\0')
                lock.flush()
            lock.seek(0)
            # LK_LOCK retries for only ten seconds. Explicit blocking retries
            # allow a legitimate first liblzma build to hold the lock longer.
            import time
            while True:
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as error:
                    if error.errno not in (13, 36):
                        raise
                    time.sleep(0.2)
            try:
                yield
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('cmake')
    parser.add_argument('--build-dir')
    parser.add_argument('--compiler')
    parser.add_argument('--generator', default='Ninja Multi-Config')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = Path(args.build_dir) if args.build_dir else root / 'build/xz-encoder-host'
    build.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in ('CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
                 'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'CMAKE_GENERATOR_PLATFORM',
                 'CMAKE_GENERATOR_TOOLSET'):
        env.pop(name, None)
    # PATH, INCLUDE, LIB and LIBPATH must survive for native MSVC environments.
    with build_lock(build.with_suffix('.lock')):
        command = [args.cmake, '-S', str(root / 'core/tools/xz_encoder'),
                   '-B', str(build), '-G', args.generator,
                   f'-DCPM_SOURCE_CACHE={root / "build/.cache"}', '-DBUILD_TESTING=ON',
                   '-DCMAKE_BUILD_TYPE=Release']
        if args.generator.startswith('Visual Studio'):
            import platform
            command += ['-A', 'ARM64' if platform.machine().upper() == 'ARM64' else 'x64']
        elif args.compiler:
            command.append(f'-DCMAKE_C_COMPILER={args.compiler}')
        subprocess.run(command, env=env, check=True)
        subprocess.run([args.cmake, '--build', str(build), '--config', 'Release',
                        '--target', 'waterwall_xz_encoder'], env=env, check=True)


if __name__ == '__main__':
    main()
