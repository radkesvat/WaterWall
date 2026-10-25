#!/usr/bin/env python3
"""Regenerate fixed VMess AEAD vectors with independent Python crypto providers.

Requires cryptography, only for explicit regeneration; native tests read vectors.h.
Wire reference: V2Fly v5.53.0 proxy/vmess/aead/{kdf,encrypt,authid}.go,
proxy/vmess/encoding/{auth,server,client}.go and common/crypto/{auth,chunk}.go.
The upstream KDF known answer is asserted before generating any fixtures.
No WaterWall implementation or executable is used by this generator.
"""

import hashlib
import ipaddress
from pathlib import Path
import struct
import uuid as uuid_module
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def kdf(key, *path):
    function = lambda data: hashlib.sha256(data).digest()
    for salt in (b"VMess AEAD KDF",) + path:
        previous = function
        padded = salt.ljust(64, b"\0")
        ipad = bytes(value ^ 0x36 for value in padded)
        opad = bytes(value ^ 0x5C for value in padded)
        function = lambda data, h=previous, i=ipad, o=opad: h(o + h(i + data))
    return function(key)


assert kdf(b"Demo Key for KDF Value Test", b"Demo Path for KDF Value Test",
           b"Demo Path for KDF Value Test2", b"Demo Path for KDF Value Test3").hex() == (
    "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892")


def fnv(data):
    result = 2166136261
    for value in data:
        result = ((result ^ value) * 16777619) & 0xFFFFFFFF
    return struct.pack(">I", result)


def chacha_key(key):
    first = hashlib.md5(key).digest()
    return first + hashlib.md5(first).digest()


uuid = bytes(range(16))
cmd = hashlib.md5(uuid + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()
auth_key = kdf(cmd, b"AES Auth ID Encryption")[:16]
key = bytes(range(32, 48))
iv = bytes(range(16, 32))
nonce8 = bytes(range(48, 56))
auth_plain = struct.pack(">Q", 1700000000) + b"\x01\x02\x03\x04"
auth = Cipher(algorithms.AES(auth_key), modes.ECB()).encryptor().update(auth_plain + struct.pack(">I", zlib.crc32(auth_plain)))
plain = b"\x01" + iv + key + bytes([61, 13, 0x33, 0, 1]) + struct.pack(">H", 443) + b"\x01\x7f\0\0\x01" + b"\xee" * 3
plain += fnv(plain)


def request_part(label, iv_label, payload):
    return AESGCM(kdf(cmd, label, auth, nonce8)[:16]).encrypt(kdf(cmd, iv_label, auth, nonce8)[:12], payload, auth)


request = auth + request_part(b"VMess Header AEAD Key_Length", b"VMess Header AEAD Nonce_Length", struct.pack(">H", len(plain))) + nonce8
request += request_part(b"VMess Header AEAD Key", b"VMess Header AEAD Nonce", plain)
plain_udp = plain[:37] + b"\x02" + plain[38:-4]
plain_udp += fnv(plain_udp)
request_udp = request[:42] + request_part(b"VMess Header AEAD Key", b"VMess Header AEAD Nonce", plain_udp)
response_key = hashlib.sha256(key).digest()[:16]
response_iv = hashlib.sha256(iv).digest()[:16]
response = AESGCM(kdf(response_key, b"AEAD Resp Header Len Key")[:16]).encrypt(
    kdf(response_iv, b"AEAD Resp Header Len IV")[:12], b"\0\x04", None)
response += AESGCM(kdf(response_key, b"AEAD Resp Header Key")[:16]).encrypt(
    kdf(response_iv, b"AEAD Resp Header IV")[:12], bytes([61, 0, 0, 0]), None)


def response_envelope(payload):
    length = AESGCM(kdf(response_key, b"AEAD Resp Header Len Key")[:16]).encrypt(
        kdf(response_iv, b"AEAD Resp Header Len IV")[:12], struct.pack(">H", len(payload)), None)
    return length + AESGCM(kdf(response_key, b"AEAD Resp Header Key")[:16]).encrypt(
        kdf(response_iv, b"AEAD Resp Header IV")[:12], payload, None)


def request_envelope(address_type, address, padding, command=1, port=443):
    address_field = bytes([address_type]) + (bytes([len(address)]) if address_type == 2 else b"") + address
    payload = b"\x01" + iv + key + bytes([61, 13, (len(padding) << 4) | 3, 0, command])
    payload += struct.pack(">H", port) + address_field + padding
    payload += fnv(payload)
    return (auth + request_part(b"VMess Header AEAD Key_Length", b"VMess Header AEAD Nonce_Length",
                                struct.pack(">H", len(payload))) + nonce8 +
            request_part(b"VMess Header AEAD Key", b"VMess Header AEAD Nonce", payload))


def frames(security, options, payloads, start=0, body_key=key, body_iv=iv,
           length_key=None, length_iv=None, shake_records=0):
    length_key = body_key if length_key is None else length_key
    length_iv = body_iv if length_iv is None else length_iv
    bytes_per_record = (2 if options & 8 else 0) + (2 if options & 4 and not options & 16 else 0)
    stream = hashlib.shake_128(body_iv).digest(bytes_per_record * (shake_records + len(payloads)))
    cursor = bytes_per_record * shake_records
    for counter, payload in enumerate(payloads, start):
        padding = 0
        if options & 8:
            padding = int.from_bytes(stream[cursor:cursor + 2], "big") % 64
            cursor += 2
        nonce = struct.pack(">H", counter & 65535) + body_iv[2:12]
        algorithm = AESGCM if security == 3 else ChaCha20Poly1305
        converted = lambda value: value if security == 3 else chacha_key(value)
        encrypted = payload if security == 5 else algorithm(converted(body_key)).encrypt(nonce, payload, None)
        size = len(encrypted) + padding
        if options & 16:
            length_nonce = struct.pack(">H", counter & 65535) + length_iv[2:12]
            prefix = algorithm(converted(kdf(length_key, b"auth_len")[:16])).encrypt(
                length_nonce, struct.pack(">H", size - 16), None)
        else:
            mask = 0
            if options & 4:
                mask = int.from_bytes(stream[cursor:cursor + 2], "big")
                cursor += 2
            prefix = struct.pack(">H", size ^ mask)
        yield prefix + encrypted + bytes([0xA5]) * padding, padding


lines = ["/* Generated by generate_vectors.py; reference V2Fly v5.53.0. */", "#pragma once", ""]


def array(name, value):
    lines.append(f"static const uint8_t {name}[] = {{")
    for offset in range(0, len(value), 16):
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in value[offset:offset + 16]) + ",")
    lines.append("};\n")


for name, value in [("vector_uuid", uuid), ("vector_cmd", cmd), ("vector_auth_key", auth_key),
                    ("vector_key", key), ("vector_iv", iv), ("vector_plain_header", plain),
                    ("vector_request", request), ("vector_response", response),
                    ("vector_plain_header_udp", plain_udp), ("vector_request_udp", request_udp)]:
    array(name, value)

array("vector_request_ipv6", request_envelope(3, bytes(range(16)), b""))
array("vector_request_domain_max", request_envelope(2, b"a" * 255, bytes(range(15))))
array("vector_request_packetaddr", request_envelope(2, b"sp.packet-addr.v2fly.arpa", b"", command=2, port=0))
array("vector_request_zero_port", request_envelope(1, b"\xc0\x00\x02\x7b", b"", command=2, port=0))
# Authenticated malformed uses of the reserved domain must never route normally.
array("vector_request_packetaddr_udp_wrong_port", request_envelope(2, b"sp.packet-addr.v2fly.arpa", b"", command=2, port=53))
array("vector_request_packetaddr_tcp_wrong_port", request_envelope(2, b"sp.packet-addr.v2fly.arpa", b"", command=1, port=443))
array("vector_request_packetaddr_tcp_zero_port", request_envelope(2, b"sp.packet-addr.v2fly.arpa", b"", command=1, port=0))
array("vector_response_command", response_envelope(bytes([61, 0xFF, 1, 3]) + b"abc"))
array("vector_response_command_max", response_envelope(bytes([61, 0xFF, 255, 255]) + bytes(range(255))))
array("vector_response_wrong_marker", response_envelope(bytes([62, 0, 0, 0])))
array("vector_response_short_command", response_envelope(bytes([61, 0, 1, 4]) + b"abc"))
array("vector_response_zero_command", response_envelope(bytes([61, 0, 0, 1, 0])))
array("vector_response_too_short", response_envelope(bytes([61, 0, 0])))
array("vector_response_too_large", response_envelope(bytes(260)))
array("vector_response_key", response_key)
array("vector_response_iv", response_iv)
for security in (3, 4):
    for options in (13, 29):
        array(f"vector_response_frame_{security}_{options}",
              next(frames(security, options, [b"reply"], body_key=response_key, body_iv=response_iv,
                          length_key=key, length_iv=iv))[0])

payloads = [b"Hello VMess", bytes(range(31)), b""]
records = []
for security in (3, 4, 5):
    for options in ((1, 5, 13, 17, 21, 29) if security != 5 else (1, 5, 13)):
        command = 2 if security == 5 and options == 13 else 1
        for index, (wire, padding) in enumerate(frames(security, options, payloads)):
            name = f"vector_frame_{security}_{options}_{index}"
            array(name, wire)
            records.append(f"    {{{security}, {options}, {command}, {index}, {padding}, {name}, sizeof({name})}},")

lines.extend(["typedef struct { uint8_t security, options, command, index, padding; const uint8_t *wire; size_t length; } vmess_vector_t;",
              "static const vmess_vector_t vector_frames[] = {", *records, "};", ""])
array("vector_last_counter", next(frames(3, 1, [b"last"], 65535))[0])
array("vector_last_counter_auth_aes", next(frames(3, 29, [b"last"], 65535))[0])
array("vector_last_counter_auth_chacha", next(frames(4, 29, [b"last"], 65535))[0])
large = next(frames(3, 17, [b"Z" * 65535]))[0]
array("vector_large_prefix", large[:18])
array("vector_large_hash", hashlib.sha256(large).digest())

# Compact independent checkpoints after all preceding SHAKE consumption. Keep
# frames(start=65535) above as seeded-state cases, whose SHAKE offset is zero.
boundaries = (65534, 65535, 65536, 65537, 131070, 131071, 131072, 131073)
records = []
for direction in (0, 1):
    for security in (3, 4):
        for options in (1, 5, 13, 17, 21, 29):
            kwargs = {} if direction == 0 else dict(body_key=response_key, body_iv=response_iv,
                                                    length_key=key, length_iv=iv)
            for ordinal in boundaries:
                wire, padding = next(frames(security, options, [b"x"], start=ordinal, shake_records=ordinal, **kwargs))
                name = f"vector_wrap_{direction}_{security}_{options}_{ordinal}"
                # Random padding does not belong in a deterministic checkpoint.
                array(name, wire[:len(wire) - padding] if padding else wire)
                records.append(f"    {{{direction}, {security}, {options}, {ordinal}, {padding}, {name}, sizeof({name})}},")
lines.extend(["typedef struct { uint8_t direction, security, options; uint32_t ordinal; uint8_t padding; const uint8_t *wire; size_t length; } vmess_wrap_vector_t;",
              "static const vmess_wrap_vector_t vector_wrap_checkpoints[] = {", *records, "};", ""])

# UUIDv5 known answers use Python's independent standard implementation.
for name, text in (("test", "test"), ("waterwall", "waterwall"), ("one", "a"),
                   ("persian", "۱۲۳"), ("composed", "é"), ("decomposed", "e\u0301"),
                   ("max", "a" * 30)):
    array("vector_short_id_" + name, uuid_module.uuid5(uuid_module.UUID(int=0), text).bytes)

# sing-vmess a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017 packetaddr +
# sing ab3827767cea serializer.go: family, address, then big-endian port.
array("vector_packetaddr_v4", b"\x01" + ipaddress.ip_address("192.0.2.123").packed + struct.pack(">H", 5353))
array("vector_packetaddr_v6", b"\x02" + ipaddress.ip_address("2001:db8::1234").packed + struct.pack(">H", 443))
Path(__file__).with_name("vectors.h").write_text("\n".join(lines), encoding="utf-8")
