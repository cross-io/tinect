#!/usr/bin/env python3
"""Small TCP/UDP echo fixture used by the privileged FakeIP test."""

import selectors
import socket
import sys


port = int(sys.argv[1])
selector = selectors.DefaultSelector()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", port))
selector.register(udp, selectors.EVENT_READ, "udp")

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("0.0.0.0", port))
tcp.listen()
tcp.setblocking(False)
selector.register(tcp, selectors.EVENT_READ, "listen")

while True:
    for key, _ in selector.select():
        if key.data == "udp":
            data, peer = udp.recvfrom(65535)
            udp.sendto(data, peer)
        elif key.data == "listen":
            stream, _ = tcp.accept()
            stream.setblocking(False)
            selector.register(stream, selectors.EVENT_READ, "stream")
        else:
            stream = key.fileobj
            data = stream.recv(65535)
            if data:
                stream.sendall(data)
            else:
                selector.unregister(stream)
                stream.close()
