#!/usr/bin/env python3
"""Tiny deterministic UDP DNS fixture for the privileged FakeIP test."""

import socket
import struct
import sys


address = (sys.argv[1], int(sys.argv[2]))
answer = socket.inet_aton(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(address)
while True:
    request, peer = sock.recvfrom(4096)
    cursor = 12
    while request[cursor] != 0:
        cursor += request[cursor] + 1
    question_end = cursor + 5
    qtype = struct.unpack("!H", request[cursor + 1 : cursor + 3])[0]
    answers = 1 if qtype == 1 else 0
    response = request[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, answers, 0, 0)
    response += request[12:question_end]
    if answers:
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + answer
    sock.sendto(response, peer)
