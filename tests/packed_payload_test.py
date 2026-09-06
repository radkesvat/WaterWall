"""Direct payload identification, roundtrip and publication regression checks."""
import argparse
import importlib.util
import lzma
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('payload', ROOT / 'core/generate_packed_payload.py')
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def pe_image(x64=True):
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'
    optional_size = 240 if x64 else 224
    struct.pack_into('<HHIIIHH', data, 68, 0x8664 if x64 else 0x14c, 1, 0, 0, 0, optional_size, 2)
    struct.pack_into('<H', data, 88, 0x20b if x64 else 0x10b)
    struct.pack_into('<I', data, 104, 4096)
    struct.pack_into('<II', data, 144, 8192, 512)
    section = 88 + optional_size
    struct.pack_into('<IIII', data, section+8, 512, 4096, 512, 512)
    struct.pack_into('<I', data, section+36, 0x60000020)
    return data


class PayloadTest(unittest.TestCase):
    def test_targets_and_bad_headers(self):
        for x64 in (True, False):
            target = 'windows-x86_64' if x64 else 'windows-x86'
            valid = pe_image(x64)
            payload.validate_executable(valid, target)
            mutations = [(0, b'XX'), (60, struct.pack('<I', 0xfffffff0)),
                         (68, b'\x64\xaa'), (86, b'\x02\x20'), (88, b'\0\0'),
                         (104, b'\0\0\0\0'), (144, b'\0\0\0\0')]
            section = 88 + (240 if x64 else 224)
            mutations += [(section+20, struct.pack('<I', 0xfffffff0)),
                          (section+12, struct.pack('<I', 0xfffffff0)),
                          (section+36, b'\0\0\0\0')]
            for offset, replacement in mutations:
                with self.subTest(x64=x64, offset=offset):
                    bad = valid.copy()
                    bad[offset:offset+len(replacement)] = replacement
                    with self.assertRaises(ValueError):
                        payload.validate_executable(bad, target)
            for length in (0, 63, 80, 200, 511, 1023):
                with self.assertRaises(ValueError):
                    payload.validate_executable(valid[:length], target)

    def test_publication(self):
        with tempfile.TemporaryDirectory(prefix='packed paths with spaces ') as temporary:
            root = Path(temporary)
            executable = root / 'private application.exe'
            original = bytes(pe_image())
            executable.write_bytes(original)
            out = root / 'packed output.c'
            out.write_text('previous valid output')
            arguments = ['generator', '--executable', str(executable), '--encoder', ENCODER,
                         '--target', 'windows-x86_64', '--finalization', 'msvc', '--output', str(out)]
            with patch.object(sys, 'argv', arguments):
                payload.main()
            text = out.read_text()
            encoded = bytes(int(item) for item in text.split('{', 1)[1].split('}', 1)[0].replace('\n', '').split(',') if item)
            self.assertEqual(lzma.decompress(encoded), original)
            decoder = lzma.LZMADecompressor()
            decoder.decompress(encoded)
            self.assertEqual(decoder.check, lzma.CHECK_CRC32)
            self.assertTrue(decoder.eof)
            self.assertEqual(decoder.unused_data, b'')
            self.assertEqual(executable.read_bytes(), original)
            for mode in ('encoder', 'strip'):
                failure_args = arguments.copy()
                if mode == 'strip':
                    failure_args[failure_args.index('msvc')] = 'gnu'
                    failure_args += ['--strip', 'missing strip tool']
                with patch.object(sys, 'argv', failure_args), patch.object(payload.subprocess, 'run', side_effect=OSError('injected failure')):
                    with self.assertRaises(OSError):
                        payload.main()
                self.assertEqual(out.read_text(), text)
                self.assertEqual(executable.read_bytes(), original)
            # A finalizer producing invalid PE bytes must not reach the encoder.
            calls = []
            def corrupt(command, **kwargs):
                calls.append(command)
                Path(command[-1]).write_bytes(b'broken')
            with patch.object(sys, 'argv', failure_args), patch.object(payload.subprocess, 'run', side_effect=corrupt):
                with self.assertRaises(ValueError):
                    payload.main()
            self.assertEqual(len(calls), 1)
            self.assertEqual(out.read_text(), text)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['packed output.c', 'private application.exe'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--encoder', required=True)
    args, remaining = parser.parse_known_args()
    ENCODER = args.encoder
    unittest.main(argv=[sys.argv[0]] + remaining)
