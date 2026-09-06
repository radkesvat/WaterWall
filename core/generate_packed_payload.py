"""Finalize and atomically publish a build-owned executable payload."""
import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


def validate_executable(data, target):
    """Identify a bounded executable image; the OS remains its loader."""
    if target == 'linux-x86_64':
        if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or
                struct.unpack_from('<H', data, 16)[0] not in (2, 3) or
                struct.unpack_from('<H', data, 18)[0] != 62 or
                struct.unpack_from('<Q', data, 24)[0] == 0):
            raise ValueError('payload must be a Linux x86-64 ELF executable')
        return
    identities = {'windows-x86_64': (0x8664, 0x20b, 112),
                  'windows-x86': (0x14c, 0x10b, 96)}
    if target not in identities:
        raise ValueError('unsupported payload target')
    machine, magic, minimum = identities[target]
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError('missing DOS header')
    pe = struct.unpack_from('<I', data, 60)[0]
    if pe < 64 or pe > len(data) - 24 or data[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid PE header offset/signature')
    actual, count, _, _, _, optional_size, flags = struct.unpack_from('<HHIIIHH', data, pe+4)
    optional = pe + 24
    sections = optional + optional_size
    if (actual != machine or not flags & 2 or flags & 0x2000 or
            not 0 < count <= 96 or optional_size < minimum or
            sections + count * 40 > len(data)):
        raise ValueError('wrong machine, DLL, or truncated PE headers')
    if struct.unpack_from('<H', data, optional)[0] != magic:
        raise ValueError('inconsistent PE optional header')
    entry = struct.unpack_from('<I', data, optional+16)[0]
    image_size, headers_size = struct.unpack_from('<II', data, optional+56)
    if not 0 < entry < image_size or not sections + count*40 <= headers_size <= len(data):
        raise ValueError('invalid PE entry point or header extent')
    executable_entry = False
    for index in range(count):
        section = sections + index*40
        virtual_size, address, size, offset = struct.unpack_from('<IIII', data, section+8)
        characteristics = struct.unpack_from('<I', data, section+36)[0]
        extent = max(virtual_size, size)
        if (address + extent > image_size or address + extent > 0xffffffff or
                (size and (offset < headers_size or offset + size > len(data)))):
            raise ValueError('invalid PE section range')
        if address <= entry < address + extent and characteristics & 0x20000000:
            executable_entry = True
    if not executable_entry:
        raise ValueError('PE entry point is outside executable sections')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', required=True)
    parser.add_argument('--encoder', required=True)
    parser.add_argument('--strip')
    parser.add_argument('--finalization', choices=('gnu', 'msvc'), default='gnu')
    parser.add_argument('--target', choices=('linux-x86_64', 'windows-x86_64', 'windows-x86'),
                        default='linux-x86_64')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.finalization == 'gnu' and not args.strip:
        parser.error('GNU finalization requires --strip')
    if args.finalization == 'msvc' and not args.target.startswith('windows-'):
        parser.error('MSVC finalization requires a Windows target')
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='payload-', dir=out.parent) as temporary:
        stage = Path(temporary)
        target_bin = stage / 'waterwall_executable'
        shutil.copyfile(args.executable, target_bin)
        target_bin.chmod(0o755)
        validate_executable(target_bin.read_bytes(), args.target)
        # MSVC's private PDB remains alongside the original application. Its PE
        # loader directories are preserved; no GNU flags are sent to MSVC tools.
        if args.finalization == 'gnu':
            subprocess.run([args.strip, '--strip-unneeded', str(target_bin)], check=True)
        validate_executable(target_bin.read_bytes(), args.target)
        payload = stage / 'payload.xz'
        subprocess.run([args.encoder, str(target_bin), str(payload)], check=True)
        data = payload.read_bytes()
        raw_size = target_bin.stat().st_size
        if not data or not raw_size:
            raise RuntimeError('empty runtime payload')
        source = stage / 'payload.c'
        with source.open('w', encoding='ascii', newline='\n') as stream:
            stream.write('#include "packed_payload.h"\nconst unsigned char waterwallPackedBytes[] = {\n')
            for i in range(0, len(data), 24):
                stream.write(','.join(str(b) for b in data[i:i+24]) + ',\n')
            stream.write('};\n')
            stream.write(f'const size_t waterwallPackedLength = {len(data)};\n')
            stream.write(f'const uint64_t waterwallRuntimeLength = {raw_size}ULL;\n')
            stream.write(f'const char waterwallPackedTarget[] = "{args.target}";\n')
        os.replace(source, out)


if __name__ == '__main__':
    main()
