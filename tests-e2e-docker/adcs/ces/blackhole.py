"""A KDC that never answers (Story 13.1 AC #9).

It listens on port 88 over TCP and UDP, accepts every connection and
reads every datagram, and never replies. A refused connection would let
the client fail fast; this one makes it wait, which is what the bound of
an operation has to survive.
"""

import logging
import socket
import threading

log = logging.getLogger("blackhole")


def swallow_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 88))
    while True:
        _, peer = sock.recvfrom(65535)
        log.info("udp datagram from %s dropped", peer[0])


def hold(connection, peer):
    with connection:
        while connection.recv(65535):
            pass
    if peer[0] != "127.0.0.1":
        log.info("tcp connection from %s closed by the client", peer[0])


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    threading.Thread(target=swallow_udp, daemon=True).start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 88))
    listener.listen(64)
    while True:
        connection, peer = listener.accept()
        # The healthcheck connects every few seconds from loopback.
        if peer[0] != "127.0.0.1":
            log.info("tcp connection from %s held open", peer[0])
        threading.Thread(target=hold, args=(connection, peer), daemon=True).start()


if __name__ == "__main__":
    main()
