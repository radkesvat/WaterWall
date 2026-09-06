"""Direct payload identification, roundtrip and publication regression checks."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import lzma
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

from packed_build_target_test import check_windows_launcher

ROOT = Path(__file__).resolve().parents[1]


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


def launcher_image(x64, debug_types=()):
    data = pe_image(x64)
    directories = 88 + (112 if x64 else 96)
    struct.pack_into('<H', data, 88+70, 0x140)  # ASLR and DEP.
    struct.pack_into('<II', data, directories+5*8, 4096+400, 12)
    if debug_types:
        # The table is inside a section: its RVA is not its file offset.
        struct.pack_into('<II', data, directories+6*8, 4096, len(debug_types)*28)
        for index, kind in enumerate(debug_types):
            struct.pack_into('<IIHHIIII', data, 512+index*28, 0, 0, 0, 0,
                             kind, 4, 4096+256, 512+256)
    return data


class PackedLauncherTest(unittest.TestCase):
    def test_non_symbol_metadata(self):
        for x64 in (False, True):
            for records in ((), (12,), (13,), (14,), (16,), (20,), (12, 13, 14, 16, 20)):
                with self.subTest(x64=x64, records=records):
                    data = launcher_image(x64, records)
                    original = bytes(data)
                    check_windows_launcher(data)
                    self.assertEqual(data, original)
            # A REPRO marker is allowed to have no associated data.
            data = launcher_image(x64, (16,))
            struct.pack_into('<III', data, 512+16, 0, 0, 0)
            check_windows_launcher(data)

    def test_symbol_records_are_rejected(self):
        for x64 in (False, True):
            for kind in (1, 2, 4, 17, 19, 99):
                with self.subTest(x64=x64, kind=kind):
                    with self.assertRaisesRegex(AssertionError, f'record type {kind}'):
                        check_windows_launcher(launcher_image(x64, (13, kind)))

    def test_invalid_debug_directory_is_rejected(self):
        for x64 in (False, True):
            directories = 88 + (112 if x64 else 96)
            for rva, size in ((0, 28), (4096, 0), (4096, 27), (4096+512, 28),
                              (4096, 28*100)):
                with self.subTest(x64=x64, rva=rva, size=size):
                    data = launcher_image(x64, (13,))
                    struct.pack_into('<II', data, directories+6*8, rva, size)
                    with self.assertRaises(AssertionError):
                        check_windows_launcher(data)
            data = launcher_image(x64, (13,))
            struct.pack_into('<I', data, 512+24, len(data)-1)
            with self.assertRaises(AssertionError):
                check_windows_launcher(data)

    def test_other_stripping_and_image_checks_remain(self):
        for x64 in (False, True):
            directories = 88 + (112 if x64 else 96)
            sections = 88 + (240 if x64 else 224)
            for offset, replacement in ((88+70, b'\0\0'), (directories+5*8, b'\0'*8),
                                        (64+16, struct.pack('<I', 1)),
                                        (sections, b'.debug\0\0')):
                with self.subTest(x64=x64, offset=offset):
                    data = launcher_image(x64)
                    data[offset:offset+len(replacement)] = replacement
                    with self.assertRaises(AssertionError):
                        check_windows_launcher(data)


class PayloadTest(unittest.TestCase):
    def validate(self, data, target, valid=True):
        with tempfile.TemporaryDirectory(prefix='payload identification ') as temporary:
            path = Path(temporary) / 'application'
            path.write_bytes(data)
            result = subprocess.run([PAYLOAD_TOOL, 'validate', target, str(path)],
                                    capture_output=True)
            self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_targets_and_bad_headers(self):
        for x64 in (True, False):
            target = 'windows-x86_64' if x64 else 'windows-x86'
            valid = pe_image(x64)
            self.validate(valid, target)
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
                    self.validate(bad, target, valid=False)
            for length in (0, 63, 80, 200, 511, 1023):
                self.validate(valid[:length], target, valid=False)

    def test_elf_headers(self):
        image = bytearray(64)
        image[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<HH', image, 16, 2, 62)
        struct.pack_into('<Q', image, 24, 0x401000)
        self.validate(image, 'linux-x86_64')
        struct.pack_into('<H', image, 16, 3)
        self.validate(image, 'linux-x86_64')
        for offset, replacement in ((0, b'bad!'), (4, b'\x01'), (5, b'\x02'),
                                    (16, b'\x01\0'), (18, b'\x03\0'), (24, b'\0'*8)):
            data = image.copy()
            data[offset:offset+len(replacement)] = replacement
            self.validate(data, 'linux-x86_64', valid=False)
        self.validate(image[:63], 'linux-x86_64', valid=False)
        self.validate(image, 'unknown-target', valid=False)
        self.validate(image, 'windows-x86', valid=False)

    def test_publication(self):
        with tempfile.TemporaryDirectory(prefix='packed paths with spaces ') as temporary:
            root = Path(temporary)
            executable = root / 'private application.exe'
            # An incompressible overlay exercises the emitter's 64 KiB reads.
            random_bytes = random.Random(0)
            original = bytes(pe_image()) + bytes(random_bytes.getrandbits(8) for _ in range(96*1024))
            executable.write_bytes(original)
            out = root / 'packed output.c'
            out.write_text('previous valid output')
            settings = {'WW_EXECUTABLE': str(executable), 'WW_ENCODER': ENCODER,
                        'WW_PAYLOAD_TOOL': PAYLOAD_TOOL, 'WW_PACKED_TARGET': 'windows-x86_64',
                        'WW_FINALIZATION': 'msvc', 'WW_OUTPUT': str(out)}

            def command_for(overrides=None):
                values = settings.copy()
                values.update(overrides or {})
                command = [CMAKE] + [f'-D{key}={value}' for key, value in values.items()]
                command += ['-P', str(ROOT / 'core/generate_packed_payload.cmake')]
                return command

            def generate(overrides=None, success=True):
                result = subprocess.run(command_for(overrides), capture_output=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                self.assertFalse(Path(str(out) + '.stage').exists())
                self.assertEqual(executable.read_bytes(), original)
                return result

            generate()
            text = out.read_text()
            encoded = bytes(int(item) for item in text.split('{', 1)[1].split('}', 1)[0].replace('\n', '').split(',') if item)
            self.assertGreater(len(encoded), 65536)
            self.assertEqual(lzma.decompress(encoded), original)
            decoder = lzma.LZMADecompressor()
            decoder.decompress(encoded)
            self.assertEqual(decoder.check, lzma.CHECK_CRC32)
            self.assertTrue(decoder.eof)
            self.assertEqual(decoder.unused_data, b'')
            self.assertIn(f'waterwallPackedLength = {len(encoded)};', text)
            self.assertIn(f'waterwallRuntimeLength = {len(original)}ULL;', text)
            self.assertIn('waterwallPackedTarget[] = "windows-x86_64";', text)
            generate()
            self.assertEqual(out.read_text(), text)
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: subprocess.run(command_for(), capture_output=True), range(2)))
            for result in results:
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(Path(str(out) + '.stage').exists())
            self.assertEqual(out.read_text(), text)
            for overrides in ({'WW_ENCODER': 'missing encoder'},
                              {'WW_PAYLOAD_TOOL': 'missing payload tool'},
                              {'WW_FINALIZATION': 'gnu', 'WW_STRIP': 'missing strip tool'}):
                generate(overrides, success=False)
                self.assertEqual(out.read_text(), text)

            # A finalizer producing invalid bytes must fail before the encoder.
            corrupt = root / 'corrupt finalizer.cmake'
            corrupt.write_text('file(WRITE "${CMAKE_ARGV5}" "broken")\n')
            result = generate({'WW_FINALIZATION': 'gnu', 'WW_STRIP': f'{CMAKE};-P;{corrupt};--',
                               'WW_ENCODER': 'encoder must not run'}, success=False)
            self.assertIn(b'Invalid executable', result.stderr)
            self.assertNotIn(b'encoder must not run', result.stderr)
            self.assertEqual(out.read_text(), text)
            out.unlink()
            generate({'WW_ENCODER': 'missing encoder'}, success=False)
            self.assertFalse(out.exists())

    def test_embedding_preserves_existing_files(self):
        with tempfile.TemporaryDirectory(prefix='payload exclusive output ') as temporary:
            root = Path(temporary)
            executable = root / 'application.exe'
            executable.write_bytes(pe_image())
            compressed = root / 'payload.xz'
            subprocess.run([ENCODER, str(executable), str(compressed)], check=True)
            for output in (executable, compressed):
                original = output.read_bytes()
                result = subprocess.run([PAYLOAD_TOOL, 'embed', 'windows-x86_64',
                                         str(executable), str(compressed), str(output)],
                                        capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output.read_bytes(), original)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--encoder', required=True)
    parser.add_argument('--payload-tool', required=True)
    parser.add_argument('--cmake', default='cmake')
    args, remaining = parser.parse_known_args()
    ENCODER = args.encoder
    PAYLOAD_TOOL = args.payload_tool
    CMAKE = args.cmake
    unittest.main(argv=[sys.argv[0]] + remaining)
