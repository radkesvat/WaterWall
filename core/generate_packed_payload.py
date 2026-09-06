"""Finalize and publish one build-owned runtime payload; never modify the input."""
import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--executable', required=True)
p.add_argument('--encoder', required=True)
p.add_argument('--strip', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
out = Path(a.output)
out.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='payload-', dir=out.parent) as temporary:
    stage = Path(temporary)
    target_bin = stage / 'waterwall_executable'
    shutil.copyfile(a.executable, target_bin)
    target_bin.chmod(0o755)
    with target_bin.open('rb') as executable:
        header = executable.read(64)
    if (len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or
            struct.unpack_from('<H', header, 16)[0] not in (2, 3) or
            struct.unpack_from('<H', header, 18)[0] != 62 or
            struct.unpack_from('<Q', header, 24)[0] == 0):
        raise RuntimeError('payload must be a Linux x86-64 ELF executable')
    subprocess.run([a.strip, '--strip-unneeded', str(target_bin)], check=True)
    payload = stage / 'payload.xz'
    subprocess.run([a.encoder, str(target_bin), str(payload)], check=True)
    data = payload.read_bytes()
    raw_size = target_bin.stat().st_size
    if not data or not raw_size:
        raise RuntimeError('empty runtime payload')
    source = stage / 'payload.c'
    with source.open('w') as f:
        f.write('#include "packed_payload.h"\nconst unsigned char waterwallPackedBytes[] = {\n')
        for i in range(0, len(data), 24):
            f.write(','.join(str(b) for b in data[i:i+24]) + ',\n')
        f.write('};\n')
        f.write(f'const size_t waterwallPackedLength = {len(data)};\n')
        f.write(f'const uint64_t waterwallRuntimeLength = {raw_size}ULL;\n')
        f.write('const char waterwallPackedTarget[] = "linux-x86_64";\n')
    os.replace(source, out)
