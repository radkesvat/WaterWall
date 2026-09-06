"""Serialize the shared native encoder build across packed configurations."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
(root / 'build').mkdir(exist_ok=True)
env = os.environ.copy()
for name in ('CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS',
             'CMAKE_TOOLCHAIN_FILE', 'CMAKE_GENERATOR', 'CMAKE_GENERATOR_PLATFORM',
             'CMAKE_GENERATOR_TOOLSET'):
    env.pop(name, None)
with (root / 'build/xz-encoder-host.lock').open('w') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    cwd = root / 'core/tools/xz_encoder'
    subprocess.run([sys.argv[1], '--preset', 'host'], cwd=cwd, env=env, check=True)
    subprocess.run([sys.argv[1], '--build', '--preset', 'host-release',
                    '--target', 'waterwall_xz_encoder'], cwd=cwd, env=env, check=True)
