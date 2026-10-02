"""Read-only PE launcher stripping/ASLR/DEP checks; no platform process APIs."""
import struct


def check_windows_launcher(data):
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
    section_count = struct.unpack_from('<H', data, pe+6)[0]
    section_start = optional + struct.unpack_from('<H', data, pe+20)[0]
    debug_rva, debug_size = struct.unpack_from('<II', data, directories + 6*8)
    if debug_rva or debug_size:
        if not debug_rva or not debug_size or debug_size % 28:
            raise AssertionError('launcher has an invalid PE debug directory')
        # IMAGE_DEBUG_DIRECTORY uses an RVA; translate through the raw section
        # data (or PE headers) before inspecting its 28-byte entries.
        debug_offset = None
        headers_size = struct.unpack_from('<I', data, optional+60)[0]
        if debug_rva + debug_size <= min(headers_size, len(data)):
            debug_offset = debug_rva
        else:
            for index in range(section_count):
                _, rva, raw_size, raw_offset = struct.unpack_from(
                    '<IIII', data, section_start+index*40+8)
                if rva <= debug_rva and debug_rva-rva+debug_size <= raw_size:
                    offset = raw_offset + debug_rva - rva
                    if offset + debug_size <= len(data):
                        debug_offset = offset
                        break
        if debug_offset is None:
            raise AssertionError('launcher PE debug directory is outside file-backed data')
        # /DEBUG:NONE can retain linker/compiler metadata in this directory.
        # These are VC_FEATURE, POGO, ILTCG, REPRO and EX_DLLCHARACTERISTICS
        # (including CET policy), not CodeView/PDB or COFF debug symbols.
        # https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type
        metadata_types = {12, 13, 14, 16, 20}
        for offset in range(debug_offset, debug_offset+debug_size, 28):
            kind, size, _, pointer = struct.unpack_from('<IIII', data, offset+12)
            if kind not in metadata_types:
                raise AssertionError(f'launcher has disallowed PE debug record type {kind}')
            if size and (not pointer or pointer + size > len(data)):
                raise AssertionError(f'launcher PE debug record type {kind} is outside the file')
    for index in range(section_count):
        name = data[section_start+index*40:section_start+index*40+8]
        if name.startswith((b'.debug', b'.zdebug', b'.stab')):
            raise AssertionError('launcher still has debug sections')
    if struct.unpack_from('<I', data, pe+16)[0] != 0:
        raise AssertionError('launcher still has COFF symbols')
