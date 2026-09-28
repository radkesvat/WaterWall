#!/usr/bin/env python3
"""Bounded UDP exchange and independent peer-side wire checksum oracle."""
import argparse
import json
import signal
import socket
import struct
from pathlib import Path

SIZES = (1, 27, 1400, 1472, 1473, 6000)


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def payload(size):
    return bytes((i * 37 + size) & 255 for i in range(size))


def dns(args):
    question = b'\x05check\x04test\0\0\x01\0\x01'
    query = struct.pack('!6H', 1234, 0x0100, args.questions, 0, 0, 0) + question * args.questions
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.bind((args.bind, 40002))
        sock.sendto(query, (args.address, 53))
        response, peer = sock.recvfrom(4096)
        ident, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
        if (ident != 1234 or flags & 15 or not flags & 0x8000 or
                questions != args.questions or answers != args.questions):
            raise RuntimeError('fake DNS response mismatch')


def udp(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(8)
        sock.bind((args.bind, args.port if args.role == 'server' else 40001))
        if args.role == 'server':
            Path(args.ready).touch()
        for size in SIZES:
            expected = payload(size)
            if args.role == 'client':
                sock.sendto(expected, (args.address, args.port))
            data, peer = sock.recvfrom(65535)
            if data != expected:
                raise RuntimeError('UDP payload mismatch at size %d' % size)
            if args.role == 'server':
                sock.sendto(data, peer)
        print(json.dumps({'verified': True, 'sizes': SIZES}), flush=True)


def capture(args):
    running = True
    def stop(signum, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    counts = {'tcp': 0, 'udp': 0, 'fragments': 0}
    fragments = {}
    errors = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.bind((args.interface, 0))
        sock.settimeout(.1)
        Path(args.ready).touch()
        while running:
            try:
                frame, link = sock.recvfrom(65535)
            except socket.timeout:
                continue
            if link[2] == socket.PACKET_OUTGOING or len(frame) < 34:
                continue
            ip = frame[14:]
            if ip[0] >> 4 != 4 or ip[16:20] != socket.inet_aton(args.bind) or ip[9] not in (6, 17):
                continue
            ihl = (ip[0] & 15) * 4
            total, ident, bits = struct.unpack('!HHH', ip[2:8])
            if not 20 <= ihl <= total <= len(ip) or checksum(ip[:ihl]) != 0:
                errors.append('IPv4 header/length checksum')
                continue
            body = ip[ihl:total]
            if bits & 0x3fff:
                counts['fragments'] += 1
                key = (ip[12:20], ip[9], ident)
                pieces, end = fragments.setdefault(key, ({}, None))
                offset = (bits & 0x1fff) * 8
                if offset in pieces:
                    errors.append('duplicate fragment')
                pieces[offset] = body
                if not bits & 0x2000:
                    end = offset + len(body)
                fragments[key] = (pieces, end)
                cursor = 0
                for start, chunk in sorted(pieces.items()):
                    if start != cursor:
                        break
                    cursor += len(chunk)
                if end is None or cursor != end:
                    continue
                body = b''.join(chunk for _, chunk in sorted(pieces.items()))
                del fragments[key]
            if ip[9] == 17:
                if len(body) < 8 or struct.unpack('!H', body[4:6])[0] != len(body):
                    errors.append('UDP length')
                    continue
                if body[6:8] == b'\0\0':
                    errors.append('unexpected disabled UDP checksum')
                    continue
            pseudo = ip[12:20] + bytes((0, ip[9])) + struct.pack('!H', len(body))
            if checksum(pseudo + body) != 0:
                errors.append('TCP/UDP wire checksum')
            counts['tcp' if ip[9] == 6 else 'udp'] += 1
    result = {**counts, 'errors': errors, 'incomplete': len(fragments)}
    print(json.dumps(result), flush=True)
    if errors or fragments or not all(counts.values()):
        raise RuntimeError('incomplete or invalid software-completed forwarding capture')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=('server', 'client', 'capture', 'dns'))
    parser.add_argument('--bind', required=True)
    parser.add_argument('--address')
    parser.add_argument('--port', type=int, default=5202)
    parser.add_argument('--ready')
    parser.add_argument('--interface')
    parser.add_argument('--questions', type=int, choices=(1, 32), default=1)
    args = parser.parse_args()
    if args.role == 'capture':
        capture(args)
    elif args.role == 'dns':
        dns(args)
    else:
        udp(args)
